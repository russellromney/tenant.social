use chrono::{DateTime, Utc};
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use thiserror::Error;
use uuid::Uuid;

use crate::models::*;

#[derive(Error, Debug)]
pub enum StoreError {
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),
    #[error("Not found: {0}")]
    NotFound(String),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
}

pub type StoreResult<T> = Result<T, StoreError>;

/// Thread-safe SQLite store
pub struct Store {
    conn: Arc<Mutex<Connection>>,
}

impl Store {
    /// Create a new store with the given database path
    pub fn new(db_path: &str) -> StoreResult<Self> {
        let conn = Connection::open(db_path)?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.init_schema()?;
        Ok(store)
    }

    /// Create an in-memory store for testing
    pub fn in_memory() -> StoreResult<Self> {
        let conn = Connection::open_in_memory()?;
        let store = Self {
            conn: Arc::new(Mutex::new(conn)),
        };
        store.init_schema()?;
        Ok(store)
    }

    fn init_schema(&self) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                display_name TEXT DEFAULT '',
                bio TEXT DEFAULT '',
                avatar_url TEXT DEFAULT '',
                is_admin INTEGER DEFAULT 0,
                is_locked INTEGER DEFAULT 0,
                recovery_hash TEXT DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                token TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS things (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                type TEXT NOT NULL,
                content TEXT DEFAULT '',
                metadata TEXT DEFAULT '{}',
                visibility TEXT DEFAULT 'private',
                version INTEGER DEFAULT 1,
                deleted_at TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS thing_versions (
                id TEXT PRIMARY KEY,
                thing_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                type TEXT NOT NULL,
                content TEXT DEFAULT '',
                metadata TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                created_by TEXT NOT NULL,
                FOREIGN KEY (thing_id) REFERENCES things(id)
            );

            CREATE TABLE IF NOT EXISTS photos (
                id TEXT PRIMARY KEY,
                thing_id TEXT NOT NULL,
                caption TEXT DEFAULT '',
                order_index INTEGER DEFAULT 0,
                data BLOB,
                content_type TEXT NOT NULL,
                filename TEXT NOT NULL,
                size INTEGER NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (thing_id) REFERENCES things(id)
            );

            CREATE TABLE IF NOT EXISTS api_keys (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                key_hash TEXT NOT NULL,
                key_prefix TEXT NOT NULL,
                scopes TEXT DEFAULT '[]',
                metadata TEXT DEFAULT '{}',
                last_used_at TEXT,
                expires_at TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS kinds (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                icon TEXT DEFAULT '',
                template TEXT DEFAULT 'default',
                attributes TEXT DEFAULT '[]',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS tags (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                UNIQUE(user_id, name)
            );

            CREATE TABLE IF NOT EXISTS thing_tags (
                thing_id TEXT NOT NULL,
                tag_id TEXT NOT NULL,
                PRIMARY KEY (thing_id, tag_id),
                FOREIGN KEY (thing_id) REFERENCES things(id),
                FOREIGN KEY (tag_id) REFERENCES tags(id)
            );

            CREATE TABLE IF NOT EXISTS thing_kinds (
                thing_id TEXT PRIMARY KEY,
                kind_id TEXT NOT NULL,
                FOREIGN KEY (thing_id) REFERENCES things(id),
                FOREIGN KEY (kind_id) REFERENCES kinds(id)
            );

            CREATE TABLE IF NOT EXISTS relationships (
                id TEXT PRIMARY KEY,
                from_id TEXT NOT NULL,
                to_id TEXT NOT NULL,
                type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (from_id) REFERENCES things(id),
                FOREIGN KEY (to_id) REFERENCES things(id)
            );

            CREATE TABLE IF NOT EXISTS friendships (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                friend_id TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id),
                FOREIGN KEY (friend_id) REFERENCES users(id),
                UNIQUE(user_id, friend_id)
            );

            CREATE TABLE IF NOT EXISTS channels (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT DEFAULT '',
                owner_id TEXT NOT NULL,
                visibility TEXT DEFAULT 'private',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (owner_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS channel_members (
                channel_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                role TEXT NOT NULL,
                joined_at TEXT NOT NULL,
                PRIMARY KEY (channel_id, user_id),
                FOREIGN KEY (channel_id) REFERENCES channels(id),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE INDEX IF NOT EXISTS idx_things_user_id ON things(user_id);
            CREATE INDEX IF NOT EXISTS idx_things_type ON things(type);
            CREATE INDEX IF NOT EXISTS idx_things_created_at ON things(created_at);
            CREATE INDEX IF NOT EXISTS idx_photos_thing_id ON photos(thing_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
            CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix);
            "#,
        )?;
        Ok(())
    }

    // ==================== User Operations ====================

    pub fn create_user(&self, user: &mut User) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        user.id = Uuid::new_v4().to_string();
        let now = Utc::now();
        user.created_at = now;
        user.updated_at = now;

        conn.execute(
            r#"INSERT INTO users (id, username, email, password_hash, display_name, bio,
                avatar_url, is_admin, is_locked, recovery_hash, created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)"#,
            params![
                &user.id,
                &user.username,
                &user.email,
                &user.password_hash,
                &user.display_name,
                &user.bio,
                &user.avatar_url,
                user.is_admin,
                user.is_locked,
                &user.recovery_hash,
                user.created_at.to_rfc3339(),
                user.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_user(&self, id: &str) -> StoreResult<User> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT * FROM users WHERE id = ?1",
            params![id],
            |row| self.row_to_user(row),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("User {}", id)),
            _ => StoreError::Database(e),
        })
    }

    pub fn get_user_by_username(&self, username: &str) -> StoreResult<User> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT * FROM users WHERE username = ?1",
            params![username],
            |row| self.row_to_user(row),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                StoreError::NotFound(format!("User {}", username))
            }
            _ => StoreError::Database(e),
        })
    }

    fn row_to_user(&self, row: &rusqlite::Row) -> rusqlite::Result<User> {
        Ok(User {
            id: row.get("id")?,
            username: row.get("username")?,
            email: row.get("email")?,
            password_hash: row.get("password_hash")?,
            display_name: row.get("display_name")?,
            bio: row.get("bio")?,
            avatar_url: row.get("avatar_url")?,
            is_admin: row.get("is_admin")?,
            is_locked: row.get("is_locked")?,
            recovery_hash: row.get("recovery_hash")?,
            created_at: parse_datetime(row.get::<_, String>("created_at")?),
            updated_at: parse_datetime(row.get::<_, String>("updated_at")?),
        })
    }

    pub fn count_users(&self) -> StoreResult<i64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?;
        Ok(count)
    }

    // ==================== Session Operations ====================

    pub fn create_session(&self, session: &mut Session) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        session.id = Uuid::new_v4().to_string();
        session.created_at = Utc::now();

        conn.execute(
            r#"INSERT INTO sessions (id, user_id, token, expires_at, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5)"#,
            params![
                &session.id,
                &session.user_id,
                &session.token,
                session.expires_at.to_rfc3339(),
                session.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_session_by_token(&self, token: &str) -> StoreResult<Session> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT * FROM sessions WHERE token = ?1",
            params![token],
            |row| {
                Ok(Session {
                    id: row.get("id")?,
                    user_id: row.get("user_id")?,
                    token: row.get("token")?,
                    expires_at: parse_datetime(row.get::<_, String>("expires_at")?),
                    created_at: parse_datetime(row.get::<_, String>("created_at")?),
                })
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound("Session".to_string()),
            _ => StoreError::Database(e),
        })
    }

    pub fn delete_session(&self, token: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute("DELETE FROM sessions WHERE token = ?1", params![token])?;
        Ok(())
    }

    // ==================== Thing Operations ====================

    pub fn create_thing(&self, thing: &mut Thing) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        thing.id = Uuid::new_v4().to_string();
        let now = Utc::now();
        thing.created_at = now;
        thing.updated_at = now;
        thing.version = 1;
        if thing.visibility.is_empty() {
            thing.visibility = "private".to_string();
        }

        let metadata_json = serde_json::to_string(&thing.metadata)?;

        conn.execute(
            r#"INSERT INTO things (id, user_id, type, content, metadata, visibility, version, created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
            params![
                &thing.id,
                &thing.user_id,
                &thing.thing_type,
                &thing.content,
                &metadata_json,
                &thing.visibility,
                thing.version,
                thing.created_at.to_rfc3339(),
                thing.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_thing(&self, id: &str) -> StoreResult<Thing> {
        let conn = self.conn.lock().unwrap();
        let mut thing = conn
            .query_row("SELECT * FROM things WHERE id = ?1", params![id], |row| {
                self.row_to_thing(row)
            })
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    StoreError::NotFound(format!("Thing {}", id))
                }
                _ => StoreError::Database(e),
            })?;

        // Load photos if it's a gallery
        if thing.thing_type == "gallery" {
            drop(conn);
            thing.photos = self.get_photos_by_thing_id(&thing.id)?;
        }

        Ok(thing)
    }

    pub fn update_thing(&self, thing: &mut Thing) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        thing.updated_at = Utc::now();
        thing.version += 1;

        let metadata_json = serde_json::to_string(&thing.metadata)?;

        let rows = conn.execute(
            r#"UPDATE things SET type = ?1, content = ?2, metadata = ?3, visibility = ?4,
               version = ?5, updated_at = ?6 WHERE id = ?7"#,
            params![
                &thing.thing_type,
                &thing.content,
                &metadata_json,
                &thing.visibility,
                thing.version,
                thing.updated_at.to_rfc3339(),
                &thing.id,
            ],
        )?;

        if rows == 0 {
            return Err(StoreError::NotFound(format!("Thing {}", thing.id)));
        }
        Ok(())
    }

    pub fn delete_thing(&self, id: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        let rows = conn.execute(
            "UPDATE things SET deleted_at = ?1 WHERE id = ?2",
            params![&now, id],
        )?;
        if rows == 0 {
            return Err(StoreError::NotFound(format!("Thing {}", id)));
        }
        Ok(())
    }

    pub fn list_things(
        &self,
        user_id: &str,
        thing_type: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> StoreResult<Vec<Thing>> {
        let conn = self.conn.lock().unwrap();
        let mut things = Vec::new();

        if let Some(t) = thing_type {
            let mut stmt = conn.prepare(
                r#"SELECT * FROM things WHERE user_id = ?1 AND type = ?2 AND deleted_at IS NULL
                   ORDER BY created_at DESC LIMIT ?3 OFFSET ?4"#
            )?;
            let rows = stmt.query_map(params![user_id, t, limit, offset], |row| {
                self.row_to_thing(row)
            })?;
            for row in rows {
                things.push(row?);
            }
        } else {
            let mut stmt = conn.prepare(
                r#"SELECT * FROM things WHERE user_id = ?1 AND deleted_at IS NULL
                   ORDER BY created_at DESC LIMIT ?2 OFFSET ?3"#
            )?;
            let rows = stmt.query_map(params![user_id, limit, offset], |row| {
                self.row_to_thing(row)
            })?;
            for row in rows {
                things.push(row?);
            }
        }

        // Load photos for galleries
        drop(conn);
        for thing in &mut things {
            if thing.thing_type == "gallery" {
                thing.photos = self.get_photos_by_thing_id(&thing.id)?;
            }
        }

        Ok(things)
    }

    /// Get all Things that link to the given Thing via link-type attributes in metadata
    pub fn get_backlinks(&self, user_id: &str, target_id: &str) -> StoreResult<Vec<Thing>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT * FROM things WHERE user_id = ?1 AND deleted_at IS NULL ORDER BY created_at DESC"#
        )?;

        let rows = stmt.query_map(params![user_id], |row| self.row_to_thing(row))?;

        let mut backlinks = Vec::new();
        let mut seen = std::collections::HashSet::new();

        for row in rows {
            let thing = row?;
            if self.has_link_to(&thing.metadata, target_id) && !seen.contains(&thing.id) {
                seen.insert(thing.id.clone());
                backlinks.push(thing);
            }
        }

        Ok(backlinks)
    }

    /// Check if a thing's metadata contains any link attributes pointing to target_id
    fn has_link_to(&self, metadata: &HashMap<String, serde_json::Value>, target_id: &str) -> bool {
        // Look for "attributes" in metadata which contains the attribute list
        if let Some(attrs) = metadata.get("attributes") {
            if let Some(attrs_array) = attrs.as_array() {
                for attr in attrs_array {
                    if let Some(attr_obj) = attr.as_object() {
                        // Check if this is a link-type attribute
                        if let Some(attr_type) = attr_obj.get("type") {
                            if attr_type.as_str() != Some("link") {
                                continue;
                            }
                        } else {
                            continue;
                        }

                        // Check the value field
                        if let Some(value) = attr_obj.get("value") {
                            // Value could be a single ID string
                            if let Some(id_str) = value.as_str() {
                                if id_str == target_id {
                                    return true;
                                }
                            }
                            // Or an array of IDs
                            if let Some(id_array) = value.as_array() {
                                for v in id_array {
                                    if let Some(id_str) = v.as_str() {
                                        if id_str == target_id {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        false
    }

    fn row_to_thing(&self, row: &rusqlite::Row) -> rusqlite::Result<Thing> {
        let metadata_str: String = row.get("metadata")?;
        let metadata: HashMap<String, serde_json::Value> =
            serde_json::from_str(&metadata_str).unwrap_or_default();

        let deleted_at: Option<String> = row.get("deleted_at")?;

        Ok(Thing {
            id: row.get("id")?,
            user_id: row.get("user_id")?,
            thing_type: row.get("type")?,
            content: row.get("content")?,
            metadata,
            visibility: row.get("visibility")?,
            version: row.get("version")?,
            deleted_at: deleted_at.map(parse_datetime),
            created_at: parse_datetime(row.get::<_, String>("created_at")?),
            updated_at: parse_datetime(row.get::<_, String>("updated_at")?),
            photos: Vec::new(),
        })
    }

    // ==================== Photo Operations ====================

    pub fn create_photo(&self, photo: &mut Photo) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        photo.id = Uuid::new_v4().to_string();
        photo.created_at = Utc::now();

        conn.execute(
            r#"INSERT INTO photos (id, thing_id, caption, order_index, data, content_type, filename, size, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
            params![
                &photo.id,
                &photo.thing_id,
                &photo.caption,
                photo.order_index,
                &photo.data,
                &photo.content_type,
                &photo.filename,
                photo.size,
                photo.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_photo(&self, id: &str) -> StoreResult<Photo> {
        let conn = self.conn.lock().unwrap();
        conn.query_row("SELECT * FROM photos WHERE id = ?1", params![id], |row| {
            self.row_to_photo(row)
        })
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("Photo {}", id)),
            _ => StoreError::Database(e),
        })
    }

    pub fn get_photos_by_thing_id(&self, thing_id: &str) -> StoreResult<Vec<Photo>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT * FROM photos WHERE thing_id = ?1 ORDER BY order_index ASC",
        )?;
        let rows = stmt.query_map(params![thing_id], |row| self.row_to_photo(row))?;

        let mut photos = Vec::new();
        for row in rows {
            photos.push(row?);
        }
        Ok(photos)
    }

    pub fn bulk_create_photos(&self, photos: &mut [Photo]) -> StoreResult<()> {
        if photos.is_empty() {
            return Ok(());
        }

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;

        for photo in photos.iter_mut() {
            photo.id = Uuid::new_v4().to_string();
            photo.created_at = Utc::now();

            tx.execute(
                r#"INSERT INTO photos (id, thing_id, caption, order_index, data, content_type, filename, size, created_at)
                   VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)"#,
                params![
                    &photo.id,
                    &photo.thing_id,
                    &photo.caption,
                    photo.order_index,
                    &photo.data,
                    &photo.content_type,
                    &photo.filename,
                    photo.size,
                    photo.created_at.to_rfc3339(),
                ],
            )?;
        }

        tx.commit()?;
        Ok(())
    }

    fn row_to_photo(&self, row: &rusqlite::Row) -> rusqlite::Result<Photo> {
        Ok(Photo {
            id: row.get("id")?,
            thing_id: row.get("thing_id")?,
            caption: row.get("caption")?,
            order_index: row.get("order_index")?,
            data: row.get("data")?,
            content_type: row.get("content_type")?,
            filename: row.get("filename")?,
            size: row.get("size")?,
            created_at: parse_datetime(row.get::<_, String>("created_at")?),
        })
    }

    // ==================== API Key Operations ====================

    pub fn create_api_key(&self, key: &mut ApiKey) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        key.id = Uuid::new_v4().to_string();
        key.created_at = Utc::now();

        let scopes_json = serde_json::to_string(&key.scopes)?;
        let metadata_json = serde_json::to_string(&key.metadata)?;

        conn.execute(
            r#"INSERT INTO api_keys (id, user_id, name, key_hash, key_prefix, scopes, metadata, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
            params![
                &key.id,
                &key.user_id,
                &key.name,
                &key.key_hash,
                &key.key_prefix,
                &scopes_json,
                &metadata_json,
                key.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn get_api_key_by_prefix(&self, prefix: &str) -> StoreResult<ApiKey> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT * FROM api_keys WHERE key_prefix = ?1",
            params![prefix],
            |row| self.row_to_api_key(row),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound("API Key".to_string()),
            _ => StoreError::Database(e),
        })
    }

    pub fn list_api_keys(&self, user_id: &str) -> StoreResult<Vec<ApiKey>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM api_keys WHERE user_id = ?1 ORDER BY created_at DESC")?;
        let rows = stmt.query_map(params![user_id], |row| self.row_to_api_key(row))?;

        let mut keys = Vec::new();
        for row in rows {
            keys.push(row?);
        }
        Ok(keys)
    }

    pub fn delete_api_key(&self, id: &str, user_id: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "DELETE FROM api_keys WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )?;
        if rows == 0 {
            return Err(StoreError::NotFound(format!("API Key {}", id)));
        }
        Ok(())
    }

    fn row_to_api_key(&self, row: &rusqlite::Row) -> rusqlite::Result<ApiKey> {
        let scopes_str: String = row.get("scopes")?;
        let scopes: Vec<String> = serde_json::from_str(&scopes_str).unwrap_or_default();

        let metadata_str: String = row.get("metadata")?;
        let metadata: Option<HashMap<String, serde_json::Value>> =
            serde_json::from_str(&metadata_str).ok();

        let last_used_at: Option<String> = row.get("last_used_at")?;
        let expires_at: Option<String> = row.get("expires_at")?;

        Ok(ApiKey {
            id: row.get("id")?,
            user_id: row.get("user_id")?,
            name: row.get("name")?,
            key_hash: row.get("key_hash")?,
            key_prefix: row.get("key_prefix")?,
            scopes,
            metadata,
            last_used_at: last_used_at.map(parse_datetime),
            expires_at: expires_at.map(parse_datetime),
            created_at: parse_datetime(row.get::<_, String>("created_at")?),
        })
    }

    // ==================== Kind Operations ====================

    pub fn create_kind(&self, kind: &mut Kind) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        kind.id = Uuid::new_v4().to_string();
        kind.created_at = Utc::now();
        kind.updated_at = Utc::now();

        let attributes_json = serde_json::to_string(&kind.attributes).unwrap_or_else(|_| "[]".to_string());

        conn.execute(
            r#"INSERT INTO kinds (id, user_id, name, icon, template, attributes, created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
            params![
                &kind.id,
                &kind.user_id,
                &kind.name,
                &kind.icon,
                &kind.template,
                &attributes_json,
                kind.created_at.to_rfc3339(),
                kind.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn count_kinds(&self, user_id: &str) -> StoreResult<i64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM kinds WHERE user_id = ?1",
            params![user_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn list_kinds(&self, user_id: &str) -> StoreResult<Vec<Kind>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, user_id, name, icon, template, attributes, created_at, updated_at
               FROM kinds WHERE user_id = ?1 ORDER BY name ASC"#,
        )?;

        let kinds = stmt
            .query_map(params![user_id], |row| {
                let attributes_json: String = row.get("attributes")?;
                let attributes: Vec<Attribute> = serde_json::from_str(&attributes_json).unwrap_or_default();

                Ok(Kind {
                    id: row.get("id")?,
                    user_id: row.get("user_id")?,
                    name: row.get("name")?,
                    icon: row.get("icon")?,
                    template: row.get("template")?,
                    attributes,
                    created_at: parse_datetime(row.get::<_, String>("created_at")?),
                    updated_at: parse_datetime(row.get::<_, String>("updated_at")?),
                })
            })?
            .collect::<Result<Vec<_>, _>>()?;

        Ok(kinds)
    }

    pub fn get_kind(&self, id: &str) -> StoreResult<Kind> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT id, user_id, name, icon, template, attributes, created_at, updated_at
               FROM kinds WHERE id = ?1"#,
        )?;

        stmt.query_row(params![id], |row| {
            let attributes_json: String = row.get("attributes")?;
            let attributes: Vec<Attribute> = serde_json::from_str(&attributes_json).unwrap_or_default();

            Ok(Kind {
                id: row.get("id")?,
                user_id: row.get("user_id")?,
                name: row.get("name")?,
                icon: row.get("icon")?,
                template: row.get("template")?,
                attributes,
                created_at: parse_datetime(row.get::<_, String>("created_at")?),
                updated_at: parse_datetime(row.get::<_, String>("updated_at")?),
            })
        })
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound("Kind not found".to_string()),
            _ => StoreError::Database(e),
        })
    }

    pub fn update_kind(&self, kind: &mut Kind) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        kind.updated_at = Utc::now();
        let attributes_json = serde_json::to_string(&kind.attributes).unwrap_or_else(|_| "[]".to_string());

        let rows = conn.execute(
            r#"UPDATE kinds SET name = ?1, icon = ?2, template = ?3, attributes = ?4, updated_at = ?5
               WHERE id = ?6"#,
            params![
                &kind.name,
                &kind.icon,
                &kind.template,
                &attributes_json,
                kind.updated_at.to_rfc3339(),
                &kind.id,
            ],
        )?;

        if rows == 0 {
            return Err(StoreError::NotFound("Kind not found".to_string()));
        }
        Ok(())
    }

    pub fn delete_kind(&self, id: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute("DELETE FROM kinds WHERE id = ?1", params![id])?;
        if rows == 0 {
            return Err(StoreError::NotFound("Kind not found".to_string()));
        }
        Ok(())
    }
}

fn parse_datetime(s: String) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(&s)
        .map(|dt| dt.with_timezone(&Utc))
        .unwrap_or_else(|_| Utc::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_create_and_get_user() {
        let store = Store::in_memory().unwrap();
        let mut user = User {
            id: String::new(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            display_name: "Test User".to_string(),
            bio: String::new(),
            avatar_url: String::new(),
            is_admin: false,
            is_locked: false,
            recovery_hash: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        store.create_user(&mut user).unwrap();
        assert!(!user.id.is_empty());

        let retrieved = store.get_user(&user.id).unwrap();
        assert_eq!(retrieved.username, "testuser");
    }

    #[test]
    fn test_create_and_list_things() {
        let store = Store::in_memory().unwrap();

        let mut user = User {
            id: String::new(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            display_name: String::new(),
            bio: String::new(),
            avatar_url: String::new(),
            is_admin: false,
            is_locked: false,
            recovery_hash: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.create_user(&mut user).unwrap();

        let mut thing = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "note".to_string(),
            content: "Test note".to_string(),
            metadata: HashMap::new(),
            visibility: "private".to_string(),
            version: 0,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };

        store.create_thing(&mut thing).unwrap();
        assert!(!thing.id.is_empty());

        let things = store.list_things(&user.id, None, 10, 0).unwrap();
        assert_eq!(things.len(), 1);
        assert_eq!(things[0].content, "Test note");
    }

    #[test]
    fn test_gallery_with_photos() {
        let store = Store::in_memory().unwrap();

        let mut user = User {
            id: String::new(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "hash".to_string(),
            display_name: String::new(),
            bio: String::new(),
            avatar_url: String::new(),
            is_admin: false,
            is_locked: false,
            recovery_hash: String::new(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        store.create_user(&mut user).unwrap();

        let mut gallery = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "gallery".to_string(),
            content: "My gallery".to_string(),
            metadata: HashMap::new(),
            visibility: "public".to_string(),
            version: 0,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut gallery).unwrap();

        let mut photo = Photo {
            id: String::new(),
            thing_id: gallery.id.clone(),
            caption: "Test photo".to_string(),
            order_index: 0,
            data: vec![1, 2, 3, 4],
            content_type: "image/jpeg".to_string(),
            filename: "test.jpg".to_string(),
            size: 4,
            created_at: Utc::now(),
        };
        store.create_photo(&mut photo).unwrap();

        let retrieved = store.get_thing(&gallery.id).unwrap();
        assert_eq!(retrieved.photos.len(), 1);
        assert_eq!(retrieved.photos[0].caption, "Test photo");
    }
}
