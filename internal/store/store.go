package store

import (
	"database/sql"
	"encoding/json"
	"log"
	"time"

	"tenant/internal/models"

	"github.com/google/uuid"
)

type Store struct {
	db      *sql.DB
	backend DataBackend
}

// New creates a new Store from a Config.
// Use ConfigFromEnv() to create config from environment variables.
func New(cfg Config) (*Store, error) {
	backend, err := NewDataBackend(cfg)
	if err != nil {
		return nil, err
	}

	db, err := backend.Connect()
	if err != nil {
		return nil, err
	}

	log.Printf("Database: %s", backend.Description())

	store := &Store{db: db, backend: backend}
	if err := store.migrate(); err != nil {
		return nil, err
	}

	return store, nil
}

// Backend returns the data backend
func (s *Store) Backend() DataBackend {
	return s.backend
}

func (s *Store) Close() error {
	return s.db.Close()
}

// User operations

func (s *Store) CreateUser(u *models.User) error {
	u.ID = uuid.New().String()
	u.CreatedAt = time.Now()
	u.UpdatedAt = time.Now()

	_, err := s.db.Exec(
		`INSERT INTO users (id, username, email, password_hash, display_name, bio, avatar_url, is_admin, is_locked, recovery_hash, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		u.ID, u.Username, u.Email, u.PasswordHash, u.DisplayName, u.Bio, u.AvatarURL, u.IsAdmin, u.IsLocked, u.RecoveryHash, u.CreatedAt, u.UpdatedAt,
	)
	return err
}

func (s *Store) GetUser(id string) (*models.User, error) {
	var u models.User
	err := s.db.QueryRow(
		`SELECT id, username, email, password_hash, display_name, bio, avatar_url, is_admin, is_locked, recovery_hash, created_at, updated_at
		FROM users WHERE id = ?`,
		id,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Bio, &u.AvatarURL, &u.IsAdmin, &u.IsLocked, &u.RecoveryHash, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) GetUserByUsername(username string) (*models.User, error) {
	var u models.User
	err := s.db.QueryRow(
		`SELECT id, username, email, password_hash, display_name, bio, avatar_url, is_admin, is_locked, recovery_hash, created_at, updated_at
		FROM users WHERE username = ?`,
		username,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Bio, &u.AvatarURL, &u.IsAdmin, &u.IsLocked, &u.RecoveryHash, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) GetUserByEmail(email string) (*models.User, error) {
	var u models.User
	err := s.db.QueryRow(
		`SELECT id, username, email, password_hash, display_name, bio, avatar_url, is_admin, is_locked, recovery_hash, created_at, updated_at
		FROM users WHERE email = ?`,
		email,
	).Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Bio, &u.AvatarURL, &u.IsAdmin, &u.IsLocked, &u.RecoveryHash, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *Store) UpdateUser(u *models.User) error {
	u.UpdatedAt = time.Now()
	_, err := s.db.Exec(
		`UPDATE users SET username = ?, email = ?, password_hash = ?, display_name = ?, bio = ?, avatar_url = ?, is_admin = ?, is_locked = ?, recovery_hash = ?, updated_at = ?
		WHERE id = ?`,
		u.Username, u.Email, u.PasswordHash, u.DisplayName, u.Bio, u.AvatarURL, u.IsAdmin, u.IsLocked, u.RecoveryHash, u.UpdatedAt, u.ID,
	)
	return err
}

func (s *Store) DeleteUser(id string) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id = ?`, id)
	return err
}

// ListUsers returns all users (admin only)
func (s *Store) ListUsers() ([]models.User, error) {
	rows, err := s.db.Query(
		`SELECT id, username, email, password_hash, display_name, bio, avatar_url, is_admin, is_locked, recovery_hash, created_at, updated_at
		FROM users ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []models.User
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Username, &u.Email, &u.PasswordHash, &u.DisplayName, &u.Bio, &u.AvatarURL, &u.IsAdmin, &u.IsLocked, &u.RecoveryHash, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

// CountUsers returns total number of users
func (s *Store) CountUsers() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&count)
	return count, err
}

// Session operations

func (s *Store) CreateSession(sess *models.Session) error {
	sess.ID = uuid.New().String()
	sess.Token = uuid.New().String()
	sess.CreatedAt = time.Now()

	_, err := s.db.Exec(
		`INSERT INTO sessions (id, user_id, token, expires_at, created_at) VALUES (?, ?, ?, ?, ?)`,
		sess.ID, sess.UserID, sess.Token, sess.ExpiresAt, sess.CreatedAt,
	)
	return err
}

func (s *Store) GetSessionByToken(token string) (*models.Session, error) {
	var sess models.Session
	err := s.db.QueryRow(
		`SELECT id, user_id, token, expires_at, created_at FROM sessions WHERE token = ?`,
		token,
	).Scan(&sess.ID, &sess.UserID, &sess.Token, &sess.ExpiresAt, &sess.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token = ?`, token)
	return err
}

func (s *Store) DeleteUserSessions(userID string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE user_id = ?`, userID)
	return err
}

func (s *Store) CleanExpiredSessions() error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE expires_at < ?`, time.Now())
	return err
}

func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		email TEXT NOT NULL UNIQUE,
		password_hash TEXT NOT NULL,
		display_name TEXT DEFAULT '',
		bio TEXT DEFAULT '',
		avatar_url TEXT DEFAULT '',
		is_admin INTEGER DEFAULT 0,
		is_locked INTEGER DEFAULT 0,
		recovery_hash TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS sessions (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		token TEXT NOT NULL UNIQUE,
		expires_at DATETIME NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS things (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		type TEXT NOT NULL,
		content TEXT NOT NULL,
		metadata TEXT DEFAULT '{}',
		version INTEGER DEFAULT 1,
		deleted_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS thing_versions (
		id TEXT PRIMARY KEY,
		thing_id TEXT NOT NULL,
		version INTEGER NOT NULL,
		type TEXT NOT NULL,
		content TEXT NOT NULL,
		metadata TEXT DEFAULT '{}',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		created_by TEXT NOT NULL,
		FOREIGN KEY (thing_id) REFERENCES things(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS api_keys (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		key_hash TEXT NOT NULL,
		key_prefix TEXT NOT NULL,
		scopes TEXT DEFAULT '[]',
		metadata TEXT DEFAULT '{}',
		last_used_at DATETIME,
		expires_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS kinds (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		icon TEXT DEFAULT '',
		template TEXT DEFAULT 'default',
		attributes TEXT DEFAULT '[]',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		UNIQUE(user_id, name)
	);

	CREATE TABLE IF NOT EXISTS tags (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		UNIQUE(user_id, name)
	);

	CREATE TABLE IF NOT EXISTS relationships (
		id TEXT PRIMARY KEY,
		from_id TEXT NOT NULL,
		to_id TEXT NOT NULL,
		type TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (from_id) REFERENCES things(id) ON DELETE CASCADE,
		FOREIGN KEY (to_id) REFERENCES things(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS thing_kinds (
		thing_id TEXT NOT NULL,
		kind_id TEXT NOT NULL,
		PRIMARY KEY (thing_id, kind_id),
		FOREIGN KEY (thing_id) REFERENCES things(id) ON DELETE CASCADE,
		FOREIGN KEY (kind_id) REFERENCES kinds(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS thing_tags (
		thing_id TEXT NOT NULL,
		tag_id TEXT NOT NULL,
		PRIMARY KEY (thing_id, tag_id),
		FOREIGN KEY (thing_id) REFERENCES things(id) ON DELETE CASCADE,
		FOREIGN KEY (tag_id) REFERENCES tags(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS photos (
		id TEXT PRIMARY KEY,
		thing_id TEXT NOT NULL,
		data BLOB NOT NULL,
		content_type TEXT NOT NULL,
		filename TEXT NOT NULL,
		size INTEGER NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (thing_id) REFERENCES things(id) ON DELETE CASCADE
	);

	CREATE TABLE IF NOT EXISTS views (
		id TEXT PRIMARY KEY,
		user_id TEXT NOT NULL,
		name TEXT NOT NULL,
		type TEXT NOT NULL,
		kind_id TEXT,
		config TEXT DEFAULT '{}',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
		FOREIGN KEY (kind_id) REFERENCES kinds(id) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
	CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
	CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
	CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
	CREATE INDEX IF NOT EXISTS idx_things_user_id ON things(user_id);
	CREATE INDEX IF NOT EXISTS idx_things_type ON things(type);
	CREATE INDEX IF NOT EXISTS idx_things_created_at ON things(created_at);
	CREATE INDEX IF NOT EXISTS idx_kinds_user_id ON kinds(user_id);
	CREATE INDEX IF NOT EXISTS idx_tags_user_id ON tags(user_id);
	CREATE INDEX IF NOT EXISTS idx_relationships_from ON relationships(from_id);
	CREATE INDEX IF NOT EXISTS idx_relationships_to ON relationships(to_id);
	CREATE INDEX IF NOT EXISTS idx_photos_thing_id ON photos(thing_id);
	CREATE INDEX IF NOT EXISTS idx_views_user_id ON views(user_id);
	CREATE INDEX IF NOT EXISTS idx_views_kind_id ON views(kind_id);
	`

	_, err := s.db.Exec(schema)
	if err != nil {
		return err
	}

	// Run migrations for existing tables (add new columns if they don't exist)
	// These ALTER TABLE statements will fail if columns already exist, which is fine
	migrations := []string{
		// Add version and deleted_at to things table
		"ALTER TABLE things ADD COLUMN version INTEGER DEFAULT 1",
		"ALTER TABLE things ADD COLUMN deleted_at DATETIME",
		// Add visibility to things table
		"ALTER TABLE things ADD COLUMN visibility TEXT DEFAULT 'private'",
		// Add caption and order_index to photos table
		"ALTER TABLE photos ADD COLUMN caption TEXT",
		"ALTER TABLE photos ADD COLUMN order_index INTEGER DEFAULT 0",
	}

	for _, m := range migrations {
		// Ignore errors - column may already exist
		s.db.Exec(m)
	}

	// Create indexes that depend on migrated columns
	postMigrationIndexes := `
	CREATE INDEX IF NOT EXISTS idx_things_deleted_at ON things(deleted_at);
	CREATE INDEX IF NOT EXISTS idx_things_visibility ON things(visibility);
	CREATE INDEX IF NOT EXISTS idx_thing_versions_thing_id ON thing_versions(thing_id);
	CREATE INDEX IF NOT EXISTS idx_thing_versions_version ON thing_versions(thing_id, version);
	CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);
	CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix);
	CREATE INDEX IF NOT EXISTS idx_photos_thing_order ON photos(thing_id, order_index);
	`
	s.db.Exec(postMigrationIndexes)

	return nil
}

// Thing operations

// CreateThing creates a new thing with version 1
func (s *Store) CreateThing(t *models.Thing) error {
	return s.CreateThingWithCreator(t, t.UserID)
}

// CreateThingWithCreator creates a new thing, tracking who created it (user or API key)
func (s *Store) CreateThingWithCreator(t *models.Thing, creatorID string) error {
	t.ID = uuid.New().String()
	t.Version = 1
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()

	// Default visibility to private if not set
	if t.Visibility == "" {
		t.Visibility = "private"
	}

	metadata, err := json.Marshal(t.Metadata)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`INSERT INTO things (id, user_id, type, content, metadata, visibility, version, deleted_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
		t.ID, t.UserID, t.Type, t.Content, string(metadata), t.Visibility, t.Version, t.CreatedAt, t.UpdatedAt,
	)
	if err != nil {
		return err
	}

	// Create initial version record
	return s.createThingVersion(t, creatorID)
}

// createThingVersion creates a version record for a thing
func (s *Store) createThingVersion(t *models.Thing, creatorID string) error {
	metadata, err := json.Marshal(t.Metadata)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`INSERT INTO thing_versions (id, thing_id, version, type, content, metadata, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		uuid.New().String(), t.ID, t.Version, t.Type, t.Content, string(metadata), time.Now(), creatorID,
	)
	return err
}

func (s *Store) GetThing(id string) (*models.Thing, error) {
	var t models.Thing
	var metadata string
	var deletedAt sql.NullTime
	var visibility sql.NullString

	err := s.db.QueryRow(
		`SELECT id, user_id, type, content, metadata, visibility, version, deleted_at, created_at, updated_at FROM things WHERE id = ?`,
		id,
	).Scan(&t.ID, &t.UserID, &t.Type, &t.Content, &metadata, &visibility, &t.Version, &deletedAt, &t.CreatedAt, &t.UpdatedAt)

	if err != nil {
		return nil, err
	}

	if deletedAt.Valid {
		t.DeletedAt = &deletedAt.Time
	}

	if visibility.Valid {
		t.Visibility = visibility.String
	} else {
		t.Visibility = "private"
	}

	if err := json.Unmarshal([]byte(metadata), &t.Metadata); err != nil {
		t.Metadata = make(map[string]interface{})
	}

	// Load photos for this Thing if it's a gallery
	if t.Type == "gallery" {
		photos, err := s.GetPhotosByThingID(t.ID)
		if err == nil {
			t.Photos = photos
		}
	}

	return &t, nil
}

// GetThingForUser gets a thing only if it belongs to the specified user (excludes soft-deleted)
func (s *Store) GetThingForUser(id, userID string) (*models.Thing, error) {
	var t models.Thing
	var metadata string
	var deletedAt sql.NullTime
	var visibility sql.NullString

	err := s.db.QueryRow(
		`SELECT id, user_id, type, content, metadata, visibility, version, deleted_at, created_at, updated_at FROM things WHERE id = ? AND user_id = ? AND deleted_at IS NULL`,
		id, userID,
	).Scan(&t.ID, &t.UserID, &t.Type, &t.Content, &metadata, &visibility, &t.Version, &deletedAt, &t.CreatedAt, &t.UpdatedAt)

	if err != nil {
		return nil, err
	}

	if deletedAt.Valid {
		t.DeletedAt = &deletedAt.Time
	}

	if visibility.Valid {
		t.Visibility = visibility.String
	} else {
		t.Visibility = "private"
	}

	if err := json.Unmarshal([]byte(metadata), &t.Metadata); err != nil {
		t.Metadata = make(map[string]interface{})
	}

	// Load photos for this Thing if it's a gallery
	if t.Type == "gallery" {
		photos, err := s.GetPhotosByThingID(t.ID)
		if err == nil {
			t.Photos = photos
		}
	}

	return &t, nil
}

// GetThingForUserIncludeDeleted gets a thing including soft-deleted ones
func (s *Store) GetThingForUserIncludeDeleted(id, userID string) (*models.Thing, error) {
	var t models.Thing
	var metadata string
	var deletedAt sql.NullTime
	var visibility sql.NullString

	err := s.db.QueryRow(
		`SELECT id, user_id, type, content, metadata, visibility, version, deleted_at, created_at, updated_at FROM things WHERE id = ? AND user_id = ?`,
		id, userID,
	).Scan(&t.ID, &t.UserID, &t.Type, &t.Content, &metadata, &visibility, &t.Version, &deletedAt, &t.CreatedAt, &t.UpdatedAt)

	if err != nil {
		return nil, err
	}

	if deletedAt.Valid {
		t.DeletedAt = &deletedAt.Time
	}

	if visibility.Valid {
		t.Visibility = visibility.String
	} else {
		t.Visibility = "private"
	}

	if err := json.Unmarshal([]byte(metadata), &t.Metadata); err != nil {
		t.Metadata = make(map[string]interface{})
	}

	// Load photos for this Thing if it's a gallery
	if t.Type == "gallery" {
		photos, err := s.GetPhotosByThingID(t.ID)
		if err == nil {
			t.Photos = photos
		}
	}

	return &t, nil
}

func (s *Store) ListThings(userID, thingType string, limit, offset int) ([]models.Thing, error) {
	var query string
	var args []interface{}

	if thingType != "" {
		query = `SELECT id, user_id, type, content, metadata, visibility, version, deleted_at, created_at, updated_at FROM things WHERE user_id = ? AND type = ? AND deleted_at IS NULL ORDER BY created_at DESC LIMIT ? OFFSET ?`
		args = []interface{}{userID, thingType, limit, offset}
	} else {
		query = `SELECT id, user_id, type, content, metadata, visibility, version, deleted_at, created_at, updated_at FROM things WHERE user_id = ? AND deleted_at IS NULL ORDER BY created_at DESC LIMIT ? OFFSET ?`
		args = []interface{}{userID, limit, offset}
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var things []models.Thing
	for rows.Next() {
		var t models.Thing
		var metadata string
		var deletedAt sql.NullTime
		var visibility sql.NullString
		if err := rows.Scan(&t.ID, &t.UserID, &t.Type, &t.Content, &metadata, &visibility, &t.Version, &deletedAt, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		if deletedAt.Valid {
			t.DeletedAt = &deletedAt.Time
		}
		if visibility.Valid {
			t.Visibility = visibility.String
		} else {
			t.Visibility = "private"
		}
		if err := json.Unmarshal([]byte(metadata), &t.Metadata); err != nil {
			t.Metadata = make(map[string]interface{})
		}
		// Load photos for gallery Things
		if t.Type == "gallery" {
			if photos, err := s.GetPhotosByThingID(t.ID); err == nil {
				t.Photos = photos
			}
		}
		things = append(things, t)
	}

	return things, nil
}

func (s *Store) UpdateThing(t *models.Thing) error {
	return s.UpdateThingWithCreator(t, t.UserID)
}

// UpdateThingWithCreator updates a thing and creates a new version, tracking who made the change
func (s *Store) UpdateThingWithCreator(t *models.Thing, creatorID string) error {
	t.UpdatedAt = time.Now()
	t.Version++

	metadata, err := json.Marshal(t.Metadata)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`UPDATE things SET type = ?, content = ?, metadata = ?, visibility = ?, version = ?, updated_at = ? WHERE id = ? AND user_id = ? AND deleted_at IS NULL`,
		t.Type, t.Content, string(metadata), t.Visibility, t.Version, t.UpdatedAt, t.ID, t.UserID,
	)
	if err != nil {
		return err
	}

	// Create version record
	return s.createThingVersion(t, creatorID)
}

// DeleteThing performs a soft delete
func (s *Store) DeleteThing(id, userID string) error {
	return s.SoftDeleteThing(id, userID)
}

// SoftDeleteThing marks a thing as deleted without removing it
func (s *Store) SoftDeleteThing(id, userID string) error {
	now := time.Now()
	_, err := s.db.Exec(`UPDATE things SET deleted_at = ?, updated_at = ? WHERE id = ? AND user_id = ? AND deleted_at IS NULL`, now, now, id, userID)
	return err
}

// HardDeleteThing permanently removes a thing and all its versions
func (s *Store) HardDeleteThing(id, userID string) error {
	// Versions are deleted by CASCADE
	_, err := s.db.Exec(`DELETE FROM things WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

// RestoreThing undeletes a soft-deleted thing
func (s *Store) RestoreThing(id, userID string) error {
	_, err := s.db.Exec(`UPDATE things SET deleted_at = NULL, updated_at = ? WHERE id = ? AND user_id = ? AND deleted_at IS NOT NULL`, time.Now(), id, userID)
	return err
}

func (s *Store) SearchThings(userID, query string, limit int) ([]models.Thing, error) {
	if limit == 0 {
		limit = 50
	}

	rows, err := s.db.Query(
		`SELECT id, user_id, type, content, metadata, version, deleted_at, created_at, updated_at
		FROM things
		WHERE user_id = ? AND deleted_at IS NULL AND (content LIKE ? OR type LIKE ?)
		ORDER BY created_at DESC
		LIMIT ?`,
		userID, "%"+query+"%", "%"+query+"%", limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var things []models.Thing
	for rows.Next() {
		var t models.Thing
		var metadata string
		var deletedAt sql.NullTime
		if err := rows.Scan(&t.ID, &t.UserID, &t.Type, &t.Content, &metadata, &t.Version, &deletedAt, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		if deletedAt.Valid {
			t.DeletedAt = &deletedAt.Time
		}
		if err := json.Unmarshal([]byte(metadata), &t.Metadata); err != nil {
			t.Metadata = make(map[string]interface{})
		}
		things = append(things, t)
	}

	return things, nil
}

// ListThingVersions returns all versions of a thing
func (s *Store) ListThingVersions(thingID, userID string) ([]models.ThingVersion, error) {
	// First verify the thing belongs to this user
	var exists int
	err := s.db.QueryRow(`SELECT 1 FROM things WHERE id = ? AND user_id = ?`, thingID, userID).Scan(&exists)
	if err != nil {
		return nil, err
	}

	rows, err := s.db.Query(
		`SELECT id, thing_id, version, type, content, metadata, created_at, created_by
		FROM thing_versions WHERE thing_id = ? ORDER BY version DESC`,
		thingID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var versions []models.ThingVersion
	for rows.Next() {
		var v models.ThingVersion
		var metadata string
		if err := rows.Scan(&v.ID, &v.ThingID, &v.Version, &v.Type, &v.Content, &metadata, &v.CreatedAt, &v.CreatedBy); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(metadata), &v.Metadata); err != nil {
			v.Metadata = make(map[string]interface{})
		}
		versions = append(versions, v)
	}

	return versions, nil
}

// GetThingVersion returns a specific version of a thing
func (s *Store) GetThingVersion(thingID, userID string, version int) (*models.ThingVersion, error) {
	// First verify the thing belongs to this user
	var exists int
	err := s.db.QueryRow(`SELECT 1 FROM things WHERE id = ? AND user_id = ?`, thingID, userID).Scan(&exists)
	if err != nil {
		return nil, err
	}

	var v models.ThingVersion
	var metadata string
	err = s.db.QueryRow(
		`SELECT id, thing_id, version, type, content, metadata, created_at, created_by
		FROM thing_versions WHERE thing_id = ? AND version = ?`,
		thingID, version,
	).Scan(&v.ID, &v.ThingID, &v.Version, &v.Type, &v.Content, &metadata, &v.CreatedAt, &v.CreatedBy)
	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(metadata), &v.Metadata); err != nil {
		v.Metadata = make(map[string]interface{})
	}

	return &v, nil
}

// GetBacklinks returns all Things that link to the given Thing via link-type attributes
func (s *Store) GetBacklinks(userID, targetID string) ([]models.Thing, error) {
	// Get all non-deleted things for the user
	rows, err := s.db.Query(
		`SELECT id, user_id, type, content, metadata, visibility, version, deleted_at, created_at, updated_at
		FROM things WHERE user_id = ? AND deleted_at IS NULL ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var backlinks []models.Thing
	seen := make(map[string]bool) // Prevent duplicates if multiple attributes link

	for rows.Next() {
		var t models.Thing
		var metadata string
		var deletedAt sql.NullTime
		var visibility sql.NullString

		err := rows.Scan(&t.ID, &t.UserID, &t.Type, &t.Content, &metadata, &visibility, &t.Version, &deletedAt, &t.CreatedAt, &t.UpdatedAt)
		if err != nil {
			return nil, err
		}

		if deletedAt.Valid {
			t.DeletedAt = &deletedAt.Time
		}
		if visibility.Valid {
			t.Visibility = visibility.String
		} else {
			t.Visibility = "private"
		}

		// Unmarshal metadata to check for link attributes
		if err := json.Unmarshal([]byte(metadata), &t.Metadata); err != nil {
			t.Metadata = make(map[string]interface{})
		}

		// Check if this thing has any link attributes pointing to targetID
		if s.hasLinkTo(t.Metadata, targetID) && !seen[t.ID] {
			backlinks = append(backlinks, t)
			seen[t.ID] = true
		}
	}

	return backlinks, rows.Err()
}

// hasLinkTo checks if a thing's metadata contains any link attributes pointing to targetID
func (s *Store) hasLinkTo(metadata map[string]interface{}, targetID string) bool {
	// Look for "attributes" in metadata which contains the attribute list
	if attrs, ok := metadata["attributes"].([]interface{}); ok {
		for _, attrRaw := range attrs {
			attr, ok := attrRaw.(map[string]interface{})
			if !ok {
				continue
			}

			// Check if this is a link-type attribute
			attrType, ok := attr["type"].(string)
			if !ok || attrType != "link" {
				continue
			}

			// Check the value field
			if value, ok := attr["value"]; ok {
				// Value could be a single ID or array of IDs
				if str, ok := value.(string); ok && str == targetID {
					return true
				}
				if arr, ok := value.([]interface{}); ok {
					for _, v := range arr {
						if vStr, ok := v.(string); ok && vStr == targetID {
							return true
						}
					}
				}
			}
		}
	}

	return false
}

// Kind operations

func (s *Store) CreateKind(k *models.Kind) error {
	k.ID = uuid.New().String()
	k.CreatedAt = time.Now()
	k.UpdatedAt = time.Now()

	if k.Attributes == nil {
		k.Attributes = []models.Attribute{}
	}
	if k.Template == "" {
		k.Template = "default"
	}

	attributes, err := json.Marshal(k.Attributes)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`INSERT INTO kinds (id, user_id, name, icon, template, attributes, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.UserID, k.Name, k.Icon, k.Template, string(attributes), k.CreatedAt, k.UpdatedAt,
	)
	return err
}

func (s *Store) GetKind(id string) (*models.Kind, error) {
	var k models.Kind
	var attributes string

	err := s.db.QueryRow(
		`SELECT id, user_id, name, icon, template, attributes, created_at, updated_at FROM kinds WHERE id = ?`,
		id,
	).Scan(&k.ID, &k.UserID, &k.Name, &k.Icon, &k.Template, &attributes, &k.CreatedAt, &k.UpdatedAt)

	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(attributes), &k.Attributes); err != nil {
		k.Attributes = []models.Attribute{}
	}

	return &k, nil
}

func (s *Store) GetKindForUser(id, userID string) (*models.Kind, error) {
	var k models.Kind
	var attributes string

	err := s.db.QueryRow(
		`SELECT id, user_id, name, icon, template, attributes, created_at, updated_at FROM kinds WHERE id = ? AND user_id = ?`,
		id, userID,
	).Scan(&k.ID, &k.UserID, &k.Name, &k.Icon, &k.Template, &attributes, &k.CreatedAt, &k.UpdatedAt)

	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(attributes), &k.Attributes); err != nil {
		k.Attributes = []models.Attribute{}
	}

	return &k, nil
}

func (s *Store) GetOrCreateKind(userID, name string) (*models.Kind, error) {
	var k models.Kind
	var attributes string
	err := s.db.QueryRow(
		`SELECT id, user_id, name, icon, template, attributes, created_at, updated_at FROM kinds WHERE user_id = ? AND name = ?`,
		userID, name,
	).Scan(&k.ID, &k.UserID, &k.Name, &k.Icon, &k.Template, &attributes, &k.CreatedAt, &k.UpdatedAt)
	if err == sql.ErrNoRows {
		k.UserID = userID
		k.Name = name
		if err := s.CreateKind(&k); err != nil {
			return nil, err
		}
		return &k, nil
	}
	if err := json.Unmarshal([]byte(attributes), &k.Attributes); err != nil {
		k.Attributes = []models.Attribute{}
	}
	return &k, err
}

func (s *Store) UpdateKind(k *models.Kind) error {
	k.UpdatedAt = time.Now()

	if k.Attributes == nil {
		k.Attributes = []models.Attribute{}
	}
	if k.Template == "" {
		k.Template = "default"
	}

	attributes, err := json.Marshal(k.Attributes)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`UPDATE kinds SET name = ?, icon = ?, template = ?, attributes = ?, updated_at = ? WHERE id = ? AND user_id = ?`,
		k.Name, k.Icon, k.Template, string(attributes), k.UpdatedAt, k.ID, k.UserID,
	)
	return err
}

func (s *Store) DeleteKind(id, userID string) error {
	_, err := s.db.Exec(`DELETE FROM kinds WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

func (s *Store) ListKinds(userID string) ([]models.Kind, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, name, icon, template, attributes, created_at, updated_at FROM kinds WHERE user_id = ? ORDER BY name`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var kinds []models.Kind
	for rows.Next() {
		var k models.Kind
		var attributes string
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.Icon, &k.Template, &attributes, &k.CreatedAt, &k.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(attributes), &k.Attributes); err != nil {
			k.Attributes = []models.Attribute{}
		}
		kinds = append(kinds, k)
	}

	return kinds, nil
}

// Tag operations

func (s *Store) CreateTag(t *models.Tag) error {
	t.ID = uuid.New().String()
	_, err := s.db.Exec(`INSERT INTO tags (id, user_id, name) VALUES (?, ?, ?)`, t.ID, t.UserID, t.Name)
	return err
}

func (s *Store) GetOrCreateTag(userID, name string) (*models.Tag, error) {
	var t models.Tag
	err := s.db.QueryRow(`SELECT id, user_id, name FROM tags WHERE user_id = ? AND name = ?`, userID, name).Scan(&t.ID, &t.UserID, &t.Name)
	if err == sql.ErrNoRows {
		t.UserID = userID
		t.Name = name
		if err := s.CreateTag(&t); err != nil {
			return nil, err
		}
		return &t, nil
	}
	return &t, err
}

func (s *Store) ListTags(userID string) ([]models.Tag, error) {
	rows, err := s.db.Query(`SELECT id, user_id, name FROM tags WHERE user_id = ? ORDER BY name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tags []models.Tag
	for rows.Next() {
		var t models.Tag
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name); err != nil {
			return nil, err
		}
		tags = append(tags, t)
	}

	return tags, nil
}

// Tag a Thing
func (s *Store) TagThing(thingID, tagID string) error {
	_, err := s.db.Exec(
		`INSERT OR IGNORE INTO thing_tags (thing_id, tag_id) VALUES (?, ?)`,
		thingID, tagID,
	)
	return err
}

// Set Thing Kind
func (s *Store) SetThingKind(thingID, kindID string) error {
	_, err := s.db.Exec(
		`INSERT OR REPLACE INTO thing_kinds (thing_id, kind_id) VALUES (?, ?)`,
		thingID, kindID,
	)
	return err
}

// Photo operations

func (s *Store) CreatePhoto(p *models.Photo) error {
	p.ID = uuid.New().String()
	p.CreatedAt = time.Now()

	_, err := s.db.Exec(
		`INSERT INTO photos (id, thing_id, caption, order_index, data, content_type, filename, size, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.ThingID, p.Caption, p.OrderIndex, p.Data, p.ContentType, p.Filename, p.Size, p.CreatedAt,
	)
	return err
}

func (s *Store) BulkCreatePhotos(photos []*models.Photo) error {
	if len(photos) == 0 {
		return nil
	}

	// Start a transaction for bulk insert
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(
		`INSERT INTO photos (id, thing_id, caption, order_index, data, content_type, filename, size, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
	)
	if err != nil {
		return err
	}
	defer stmt.Close()

	now := time.Now()
	for _, p := range photos {
		p.ID = uuid.New().String()
		p.CreatedAt = now

		_, err := stmt.Exec(p.ID, p.ThingID, p.Caption, p.OrderIndex, p.Data, p.ContentType, p.Filename, p.Size, p.CreatedAt)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) GetPhoto(id string) (*models.Photo, error) {
	var p models.Photo

	err := s.db.QueryRow(
		`SELECT id, thing_id, caption, order_index, data, content_type, filename, size, created_at FROM photos WHERE id = ?`,
		id,
	).Scan(&p.ID, &p.ThingID, &p.Caption, &p.OrderIndex, &p.Data, &p.ContentType, &p.Filename, &p.Size, &p.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &p, nil
}

func (s *Store) GetPhotoByThingID(thingID string) (*models.Photo, error) {
	var p models.Photo

	err := s.db.QueryRow(
		`SELECT id, thing_id, caption, order_index, data, content_type, filename, size, created_at FROM photos WHERE thing_id = ? ORDER BY order_index LIMIT 1`,
		thingID,
	).Scan(&p.ID, &p.ThingID, &p.Caption, &p.OrderIndex, &p.Data, &p.ContentType, &p.Filename, &p.Size, &p.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &p, nil
}

// GetPhotosByThingID gets all photos for a Thing, ordered by order_index
func (s *Store) GetPhotosByThingID(thingID string) ([]models.Photo, error) {
	rows, err := s.db.Query(
		`SELECT id, thing_id, caption, order_index, data, content_type, filename, size, created_at FROM photos WHERE thing_id = ? ORDER BY order_index`,
		thingID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var photos []models.Photo
	for rows.Next() {
		var p models.Photo
		err := rows.Scan(&p.ID, &p.ThingID, &p.Caption, &p.OrderIndex, &p.Data, &p.ContentType, &p.Filename, &p.Size, &p.CreatedAt)
		if err != nil {
			return nil, err
		}
		photos = append(photos, p)
	}
	return photos, rows.Err()
}

func (s *Store) DeletePhoto(id string) error {
	_, err := s.db.Exec(`DELETE FROM photos WHERE id = ?`, id)
	return err
}

func (s *Store) UpdatePhotoCaption(id, caption string) error {
	_, err := s.db.Exec(`UPDATE photos SET caption = ? WHERE id = ?`, caption, id)
	return err
}

// View operations

func (s *Store) CreateView(v *models.View) error {
	v.ID = uuid.New().String()
	v.CreatedAt = time.Now()
	v.UpdatedAt = time.Now()

	config, err := json.Marshal(v.Config)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`INSERT INTO views (id, user_id, name, type, kind_id, config, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		v.ID, v.UserID, v.Name, v.Type, v.KindID, string(config), v.CreatedAt, v.UpdatedAt,
	)
	return err
}

func (s *Store) GetView(id string) (*models.View, error) {
	var v models.View
	var config string
	var kindID sql.NullString

	err := s.db.QueryRow(
		`SELECT id, user_id, name, type, kind_id, config, created_at, updated_at FROM views WHERE id = ?`,
		id,
	).Scan(&v.ID, &v.UserID, &v.Name, &v.Type, &kindID, &config, &v.CreatedAt, &v.UpdatedAt)

	if err != nil {
		return nil, err
	}

	if kindID.Valid {
		v.KindID = &kindID.String
	}

	if err := json.Unmarshal([]byte(config), &v.Config); err != nil {
		v.Config = models.ViewConfig{}
	}

	return &v, nil
}

func (s *Store) GetViewForUser(id, userID string) (*models.View, error) {
	var v models.View
	var config string
	var kindID sql.NullString

	err := s.db.QueryRow(
		`SELECT id, user_id, name, type, kind_id, config, created_at, updated_at FROM views WHERE id = ? AND user_id = ?`,
		id, userID,
	).Scan(&v.ID, &v.UserID, &v.Name, &v.Type, &kindID, &config, &v.CreatedAt, &v.UpdatedAt)

	if err != nil {
		return nil, err
	}

	if kindID.Valid {
		v.KindID = &kindID.String
	}

	if err := json.Unmarshal([]byte(config), &v.Config); err != nil {
		v.Config = models.ViewConfig{}
	}

	return &v, nil
}

func (s *Store) UpdateView(v *models.View) error {
	v.UpdatedAt = time.Now()

	config, err := json.Marshal(v.Config)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`UPDATE views SET name = ?, type = ?, kind_id = ?, config = ?, updated_at = ? WHERE id = ? AND user_id = ?`,
		v.Name, v.Type, v.KindID, string(config), v.UpdatedAt, v.ID, v.UserID,
	)
	return err
}

func (s *Store) DeleteView(id, userID string) error {
	_, err := s.db.Exec(`DELETE FROM views WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

func (s *Store) ListViews(userID string) ([]models.View, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, name, type, kind_id, config, created_at, updated_at FROM views WHERE user_id = ? ORDER BY name`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var views []models.View
	for rows.Next() {
		var v models.View
		var config string
		var kindID sql.NullString
		if err := rows.Scan(&v.ID, &v.UserID, &v.Name, &v.Type, &kindID, &config, &v.CreatedAt, &v.UpdatedAt); err != nil {
			return nil, err
		}
		if kindID.Valid {
			v.KindID = &kindID.String
		}
		if err := json.Unmarshal([]byte(config), &v.Config); err != nil {
			v.Config = models.ViewConfig{}
		}
		views = append(views, v)
	}

	return views, nil
}

// ============================================================================
// API Key operations
// ============================================================================

// CreateAPIKey creates a new API key. Returns the raw key (only available at creation time).
func (s *Store) CreateAPIKey(k *models.APIKey, rawKey string, keyHash string) error {
	k.ID = uuid.New().String()
	k.KeyHash = keyHash
	k.KeyPrefix = rawKey[:8] // First 8 chars for identification
	k.CreatedAt = time.Now()

	if k.Scopes == nil {
		k.Scopes = []string{}
	}
	if k.Metadata == nil {
		k.Metadata = make(map[string]interface{})
	}

	scopes, err := json.Marshal(k.Scopes)
	if err != nil {
		return err
	}
	metadata, err := json.Marshal(k.Metadata)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, scopes, metadata, last_used_at, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		k.ID, k.UserID, k.Name, k.KeyHash, k.KeyPrefix, string(scopes), string(metadata), k.LastUsedAt, k.ExpiresAt, k.CreatedAt,
	)
	return err
}

// GetAPIKey gets an API key by ID
func (s *Store) GetAPIKey(id string) (*models.APIKey, error) {
	var k models.APIKey
	var scopes, metadata string
	var lastUsedAt, expiresAt sql.NullTime

	err := s.db.QueryRow(
		`SELECT id, user_id, name, key_hash, key_prefix, scopes, metadata, last_used_at, expires_at, created_at FROM api_keys WHERE id = ?`,
		id,
	).Scan(&k.ID, &k.UserID, &k.Name, &k.KeyHash, &k.KeyPrefix, &scopes, &metadata, &lastUsedAt, &expiresAt, &k.CreatedAt)
	if err != nil {
		return nil, err
	}

	if lastUsedAt.Valid {
		k.LastUsedAt = &lastUsedAt.Time
	}
	if expiresAt.Valid {
		k.ExpiresAt = &expiresAt.Time
	}
	if err := json.Unmarshal([]byte(scopes), &k.Scopes); err != nil {
		k.Scopes = []string{}
	}
	if err := json.Unmarshal([]byte(metadata), &k.Metadata); err != nil {
		k.Metadata = make(map[string]interface{})
	}

	return &k, nil
}

// GetAPIKeyForUser gets an API key only if it belongs to the specified user
func (s *Store) GetAPIKeyForUser(id, userID string) (*models.APIKey, error) {
	var k models.APIKey
	var scopes, metadata string
	var lastUsedAt, expiresAt sql.NullTime

	err := s.db.QueryRow(
		`SELECT id, user_id, name, key_hash, key_prefix, scopes, metadata, last_used_at, expires_at, created_at FROM api_keys WHERE id = ? AND user_id = ?`,
		id, userID,
	).Scan(&k.ID, &k.UserID, &k.Name, &k.KeyHash, &k.KeyPrefix, &scopes, &metadata, &lastUsedAt, &expiresAt, &k.CreatedAt)
	if err != nil {
		return nil, err
	}

	if lastUsedAt.Valid {
		k.LastUsedAt = &lastUsedAt.Time
	}
	if expiresAt.Valid {
		k.ExpiresAt = &expiresAt.Time
	}
	if err := json.Unmarshal([]byte(scopes), &k.Scopes); err != nil {
		k.Scopes = []string{}
	}
	if err := json.Unmarshal([]byte(metadata), &k.Metadata); err != nil {
		k.Metadata = make(map[string]interface{})
	}

	return &k, nil
}

// GetAPIKeyByPrefix gets an API key by its prefix (for auth lookup)
func (s *Store) GetAPIKeyByPrefix(prefix string) (*models.APIKey, error) {
	var k models.APIKey
	var scopes, metadata string
	var lastUsedAt, expiresAt sql.NullTime

	err := s.db.QueryRow(
		`SELECT id, user_id, name, key_hash, key_prefix, scopes, metadata, last_used_at, expires_at, created_at FROM api_keys WHERE key_prefix = ?`,
		prefix,
	).Scan(&k.ID, &k.UserID, &k.Name, &k.KeyHash, &k.KeyPrefix, &scopes, &metadata, &lastUsedAt, &expiresAt, &k.CreatedAt)
	if err != nil {
		return nil, err
	}

	if lastUsedAt.Valid {
		k.LastUsedAt = &lastUsedAt.Time
	}
	if expiresAt.Valid {
		k.ExpiresAt = &expiresAt.Time
	}
	if err := json.Unmarshal([]byte(scopes), &k.Scopes); err != nil {
		k.Scopes = []string{}
	}
	if err := json.Unmarshal([]byte(metadata), &k.Metadata); err != nil {
		k.Metadata = make(map[string]interface{})
	}

	return &k, nil
}

// ListAPIKeys lists all API keys for a user (without the hash)
func (s *Store) ListAPIKeys(userID string) ([]models.APIKey, error) {
	rows, err := s.db.Query(
		`SELECT id, user_id, name, key_hash, key_prefix, scopes, metadata, last_used_at, expires_at, created_at FROM api_keys WHERE user_id = ? ORDER BY created_at DESC`,
		userID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var keys []models.APIKey
	for rows.Next() {
		var k models.APIKey
		var scopes, metadata string
		var lastUsedAt, expiresAt sql.NullTime
		if err := rows.Scan(&k.ID, &k.UserID, &k.Name, &k.KeyHash, &k.KeyPrefix, &scopes, &metadata, &lastUsedAt, &expiresAt, &k.CreatedAt); err != nil {
			return nil, err
		}
		if lastUsedAt.Valid {
			k.LastUsedAt = &lastUsedAt.Time
		}
		if expiresAt.Valid {
			k.ExpiresAt = &expiresAt.Time
		}
		if err := json.Unmarshal([]byte(scopes), &k.Scopes); err != nil {
			k.Scopes = []string{}
		}
		if err := json.Unmarshal([]byte(metadata), &k.Metadata); err != nil {
			k.Metadata = make(map[string]interface{})
		}
		keys = append(keys, k)
	}

	return keys, nil
}

// UpdateAPIKey updates an API key's name, scopes, and metadata
func (s *Store) UpdateAPIKey(k *models.APIKey) error {
	scopes, err := json.Marshal(k.Scopes)
	if err != nil {
		return err
	}
	metadata, err := json.Marshal(k.Metadata)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`UPDATE api_keys SET name = ?, scopes = ?, metadata = ?, expires_at = ? WHERE id = ? AND user_id = ?`,
		k.Name, string(scopes), string(metadata), k.ExpiresAt, k.ID, k.UserID,
	)
	return err
}

// UpdateAPIKeyLastUsed updates the last_used_at timestamp
func (s *Store) UpdateAPIKeyLastUsed(id string) error {
	_, err := s.db.Exec(`UPDATE api_keys SET last_used_at = ? WHERE id = ?`, time.Now(), id)
	return err
}

// DeleteAPIKey deletes an API key
func (s *Store) DeleteAPIKey(id, userID string) error {
	_, err := s.db.Exec(`DELETE FROM api_keys WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

// ============================================================================
// Advanced Query Operations
// ============================================================================

// ThingQuery represents query parameters for listing things
type ThingQuery struct {
	UserID         string
	Type           string            // Filter by type
	MetadataFilter map[string]string // Filter by metadata fields (meta.field=value)
	Sort           string            // Sort field (prefix with - for desc, e.g., "-createdAt")
	Page           int               // Page number (1-indexed)
	Count          int               // Items per page (0 or -1 for all)
	IncludeDeleted bool              // Include soft-deleted items
}

// ThingQueryResult contains the query result with pagination info
type ThingQueryResult struct {
	Things     []models.Thing `json:"things"`
	Total      int            `json:"total"`
	Page       int            `json:"page"`
	Count      int            `json:"count"`
	TotalPages int            `json:"totalPages"`
}

// QueryThings performs an advanced query with filtering, sorting, and pagination
func (s *Store) QueryThings(q ThingQuery) (*ThingQueryResult, error) {
	// Build WHERE clause
	where := []string{"user_id = ?"}
	args := []interface{}{q.UserID}

	if !q.IncludeDeleted {
		where = append(where, "deleted_at IS NULL")
	}

	if q.Type != "" {
		where = append(where, "type = ?")
		args = append(args, q.Type)
	}

	// Metadata filters
	for field, value := range q.MetadataFilter {
		// Use JSON extraction for SQLite
		where = append(where, "json_extract(metadata, ?) = ?")
		args = append(args, "$."+field, value)
	}

	whereClause := "WHERE " + joinStrings(where, " AND ")

	// Count total
	var total int
	countQuery := "SELECT COUNT(*) FROM things " + whereClause
	if err := s.db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, err
	}

	// Build ORDER BY
	orderBy := "ORDER BY created_at DESC" // default
	if q.Sort != "" {
		desc := false
		sortField := q.Sort
		if sortField[0] == '-' {
			desc = true
			sortField = sortField[1:]
		}
		// Map sort fields to columns
		columnMap := map[string]string{
			"createdAt": "created_at",
			"updatedAt": "updated_at",
			"type":      "type",
			"content":   "content",
			"version":   "version",
		}
		if col, ok := columnMap[sortField]; ok {
			if desc {
				orderBy = "ORDER BY " + col + " DESC"
			} else {
				orderBy = "ORDER BY " + col + " ASC"
			}
		}
	}

	// Build LIMIT/OFFSET
	var limitClause string
	page := q.Page
	if page < 1 {
		page = 1
	}
	count := q.Count
	if count <= 0 {
		// Return all
		limitClause = ""
	} else {
		offset := (page - 1) * count
		limitClause = " LIMIT ? OFFSET ?"
		args = append(args, count, offset)
	}

	// Execute query
	query := `SELECT id, user_id, type, content, metadata, version, deleted_at, created_at, updated_at FROM things ` + whereClause + " " + orderBy + limitClause

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var things []models.Thing
	for rows.Next() {
		var t models.Thing
		var metadata string
		var deletedAt sql.NullTime
		if err := rows.Scan(&t.ID, &t.UserID, &t.Type, &t.Content, &metadata, &t.Version, &deletedAt, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		if deletedAt.Valid {
			t.DeletedAt = &deletedAt.Time
		}
		if err := json.Unmarshal([]byte(metadata), &t.Metadata); err != nil {
			t.Metadata = make(map[string]interface{})
		}
		things = append(things, t)
	}

	// Calculate total pages
	totalPages := 0
	if count > 0 {
		totalPages = (total + count - 1) / count
	} else {
		totalPages = 1
	}

	return &ThingQueryResult{
		Things:     things,
		Total:      total,
		Page:       page,
		Count:      count,
		TotalPages: totalPages,
	}, nil
}

// Helper to join strings
func joinStrings(strs []string, sep string) string {
	if len(strs) == 0 {
		return ""
	}
	result := strs[0]
	for i := 1; i < len(strs); i++ {
		result += sep + strs[i]
	}
	return result
}

// ============================================================================
// Upsert Operations
// ============================================================================

// UpsertThing creates a thing if it doesn't exist, or updates it if it does.
// Match is based on type + a specific metadata field value.
func (s *Store) UpsertThing(userID, thingType, matchField, matchValue string, t *models.Thing, creatorID string) (*models.Thing, bool, error) {
	// Try to find existing thing
	query := `SELECT id, user_id, type, content, metadata, version, deleted_at, created_at, updated_at
		FROM things
		WHERE user_id = ? AND type = ? AND json_extract(metadata, ?) = ? AND deleted_at IS NULL`

	var existing models.Thing
	var metadata string
	var deletedAt sql.NullTime

	err := s.db.QueryRow(query, userID, thingType, "$."+matchField, matchValue).Scan(
		&existing.ID, &existing.UserID, &existing.Type, &existing.Content, &metadata, &existing.Version, &deletedAt, &existing.CreatedAt, &existing.UpdatedAt,
	)

	if err == sql.ErrNoRows {
		// Create new
		t.UserID = userID
		t.Type = thingType
		if err := s.CreateThingWithCreator(t, creatorID); err != nil {
			return nil, false, err
		}
		return t, true, nil // created=true
	}

	if err != nil {
		return nil, false, err
	}

	// Update existing
	if err := json.Unmarshal([]byte(metadata), &existing.Metadata); err != nil {
		existing.Metadata = make(map[string]interface{})
	}
	if deletedAt.Valid {
		existing.DeletedAt = &deletedAt.Time
	}

	// Merge updates
	existing.Content = t.Content
	for k, v := range t.Metadata {
		existing.Metadata[k] = v
	}

	if err := s.UpdateThingWithCreator(&existing, creatorID); err != nil {
		return nil, false, err
	}

	return &existing, false, nil // created=false (updated)
}

// ============================================================================
// Bulk Operations
// ============================================================================

// BulkCreateThings creates multiple things in a transaction
func (s *Store) BulkCreateThings(things []*models.Thing, creatorID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, t := range things {
		t.ID = uuid.New().String()
		t.Version = 1
		t.CreatedAt = time.Now()
		t.UpdatedAt = time.Now()

		metadata, err := json.Marshal(t.Metadata)
		if err != nil {
			return err
		}

		_, err = tx.Exec(
			`INSERT INTO things (id, user_id, type, content, metadata, version, deleted_at, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, NULL, ?, ?)`,
			t.ID, t.UserID, t.Type, t.Content, string(metadata), t.Version, t.CreatedAt, t.UpdatedAt,
		)
		if err != nil {
			return err
		}

		// Create version record
		_, err = tx.Exec(
			`INSERT INTO thing_versions (id, thing_id, version, type, content, metadata, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			uuid.New().String(), t.ID, t.Version, t.Type, t.Content, string(metadata), time.Now(), creatorID,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// BulkUpdateThings updates multiple things in a transaction
func (s *Store) BulkUpdateThings(things []*models.Thing, creatorID string) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, t := range things {
		t.UpdatedAt = time.Now()
		t.Version++

		metadata, err := json.Marshal(t.Metadata)
		if err != nil {
			return err
		}

		_, err = tx.Exec(
			`UPDATE things SET type = ?, content = ?, metadata = ?, version = ?, updated_at = ? WHERE id = ? AND user_id = ? AND deleted_at IS NULL`,
			t.Type, t.Content, string(metadata), t.Version, t.UpdatedAt, t.ID, t.UserID,
		)
		if err != nil {
			return err
		}

		// Create version record
		_, err = tx.Exec(
			`INSERT INTO thing_versions (id, thing_id, version, type, content, metadata, created_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			uuid.New().String(), t.ID, t.Version, t.Type, t.Content, string(metadata), time.Now(), creatorID,
		)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// BulkDeleteThings soft-deletes multiple things by ID
func (s *Store) BulkDeleteThings(userID string, ids []string) error {
	if len(ids) == 0 {
		return nil
	}

	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now()
	for _, id := range ids {
		_, err = tx.Exec(`UPDATE things SET deleted_at = ?, updated_at = ? WHERE id = ? AND user_id = ? AND deleted_at IS NULL`, now, now, id, userID)
		if err != nil {
			return err
		}
	}

	return tx.Commit()
}

// CountThings returns the total count of things for a user (excluding deleted)
func (s *Store) CountThings(userID string) (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM things WHERE user_id = ? AND deleted_at IS NULL`, userID).Scan(&count)
	return count, err
}
