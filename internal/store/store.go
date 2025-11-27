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
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
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
	return err
}

// Thing operations

func (s *Store) CreateThing(t *models.Thing) error {
	t.ID = uuid.New().String()
	t.CreatedAt = time.Now()
	t.UpdatedAt = time.Now()

	metadata, err := json.Marshal(t.Metadata)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`INSERT INTO things (id, user_id, type, content, metadata, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		t.ID, t.UserID, t.Type, t.Content, string(metadata), t.CreatedAt, t.UpdatedAt,
	)
	return err
}

func (s *Store) GetThing(id string) (*models.Thing, error) {
	var t models.Thing
	var metadata string

	err := s.db.QueryRow(
		`SELECT id, user_id, type, content, metadata, created_at, updated_at FROM things WHERE id = ?`,
		id,
	).Scan(&t.ID, &t.UserID, &t.Type, &t.Content, &metadata, &t.CreatedAt, &t.UpdatedAt)

	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(metadata), &t.Metadata); err != nil {
		t.Metadata = make(map[string]interface{})
	}

	return &t, nil
}

// GetThingForUser gets a thing only if it belongs to the specified user
func (s *Store) GetThingForUser(id, userID string) (*models.Thing, error) {
	var t models.Thing
	var metadata string

	err := s.db.QueryRow(
		`SELECT id, user_id, type, content, metadata, created_at, updated_at FROM things WHERE id = ? AND user_id = ?`,
		id, userID,
	).Scan(&t.ID, &t.UserID, &t.Type, &t.Content, &metadata, &t.CreatedAt, &t.UpdatedAt)

	if err != nil {
		return nil, err
	}

	if err := json.Unmarshal([]byte(metadata), &t.Metadata); err != nil {
		t.Metadata = make(map[string]interface{})
	}

	return &t, nil
}

func (s *Store) ListThings(userID, thingType string, limit, offset int) ([]models.Thing, error) {
	var query string
	var args []interface{}

	if thingType != "" {
		query = `SELECT id, user_id, type, content, metadata, created_at, updated_at FROM things WHERE user_id = ? AND type = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
		args = []interface{}{userID, thingType, limit, offset}
	} else {
		query = `SELECT id, user_id, type, content, metadata, created_at, updated_at FROM things WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
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
		if err := rows.Scan(&t.ID, &t.UserID, &t.Type, &t.Content, &metadata, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(metadata), &t.Metadata); err != nil {
			t.Metadata = make(map[string]interface{})
		}
		things = append(things, t)
	}

	return things, nil
}

func (s *Store) UpdateThing(t *models.Thing) error {
	t.UpdatedAt = time.Now()

	metadata, err := json.Marshal(t.Metadata)
	if err != nil {
		return err
	}

	_, err = s.db.Exec(
		`UPDATE things SET type = ?, content = ?, metadata = ?, updated_at = ? WHERE id = ? AND user_id = ?`,
		t.Type, t.Content, string(metadata), t.UpdatedAt, t.ID, t.UserID,
	)
	return err
}

func (s *Store) DeleteThing(id, userID string) error {
	_, err := s.db.Exec(`DELETE FROM things WHERE id = ? AND user_id = ?`, id, userID)
	return err
}

func (s *Store) SearchThings(userID, query string, limit int) ([]models.Thing, error) {
	if limit == 0 {
		limit = 50
	}

	rows, err := s.db.Query(
		`SELECT id, user_id, type, content, metadata, created_at, updated_at
		FROM things
		WHERE user_id = ? AND (content LIKE ? OR type LIKE ?)
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
		if err := rows.Scan(&t.ID, &t.UserID, &t.Type, &t.Content, &metadata, &t.CreatedAt, &t.UpdatedAt); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(metadata), &t.Metadata); err != nil {
			t.Metadata = make(map[string]interface{})
		}
		things = append(things, t)
	}

	return things, nil
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
		`INSERT INTO photos (id, thing_id, data, content_type, filename, size, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		p.ID, p.ThingID, p.Data, p.ContentType, p.Filename, p.Size, p.CreatedAt,
	)
	return err
}

func (s *Store) GetPhoto(id string) (*models.Photo, error) {
	var p models.Photo

	err := s.db.QueryRow(
		`SELECT id, thing_id, data, content_type, filename, size, created_at FROM photos WHERE id = ?`,
		id,
	).Scan(&p.ID, &p.ThingID, &p.Data, &p.ContentType, &p.Filename, &p.Size, &p.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &p, nil
}

func (s *Store) GetPhotoByThingID(thingID string) (*models.Photo, error) {
	var p models.Photo

	err := s.db.QueryRow(
		`SELECT id, thing_id, data, content_type, filename, size, created_at FROM photos WHERE thing_id = ?`,
		thingID,
	).Scan(&p.ID, &p.ThingID, &p.Data, &p.ContentType, &p.Filename, &p.Size, &p.CreatedAt)

	if err != nil {
		return nil, err
	}

	return &p, nil
}

func (s *Store) DeletePhoto(id string) error {
	_, err := s.db.Exec(`DELETE FROM photos WHERE id = ?`, id)
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
