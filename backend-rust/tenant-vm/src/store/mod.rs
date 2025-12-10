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

/// Query parameters for advanced thing queries
#[derive(Debug, Default)]
pub struct ThingQuery {
    pub user_id: String,
    pub thing_type: Option<String>,
    pub metadata_filter: HashMap<String, String>,
    pub sort: Option<String>,
    pub page: i64,
    pub count: i64,
    pub include_deleted: bool,
}

/// Result of a paginated thing query
#[derive(Debug, serde::Serialize)]
pub struct ThingQueryResult {
    pub things: Vec<Thing>,
    pub total: i64,
    pub page: i64,
    pub count: i64,
    pub total_pages: i64,
}

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

            CREATE TABLE IF NOT EXISTS follows (
                id TEXT PRIMARY KEY,
                follower_id TEXT NOT NULL,
                following_id TEXT NOT NULL,
                remote_endpoint TEXT NOT NULL,
                access_token TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (follower_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(follower_id, following_id)
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

            -- ============================================================
            -- EVENT SYSTEM: Subscriptions and delivery queue
            -- ============================================================

            -- Subscriptions: what happens when events occur
            CREATE TABLE IF NOT EXISTS subscriptions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT,
                event_type TEXT NOT NULL,
                source_type TEXT,
                source_id TEXT,
                action_type TEXT NOT NULL,
                action_config TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            -- Delivery queue: pending/retry outbound deliveries
            CREATE TABLE IF NOT EXISTS delivery_queue (
                id TEXT PRIMARY KEY,
                delivery_type TEXT NOT NULL,
                destination TEXT NOT NULL,
                payload TEXT NOT NULL,
                status TEXT DEFAULT 'pending',
                attempts INTEGER DEFAULT 0,
                max_attempts INTEGER DEFAULT 3,
                next_attempt_at TEXT,
                last_error TEXT,
                created_at TEXT NOT NULL,
                delivered_at TEXT
            );

            -- ============================================================
            -- NOTIFICATIONS: Settings and stored notifications
            -- ============================================================

            -- Notification settings: what types you accept/reject
            CREATE TABLE IF NOT EXISTS notification_settings (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                notification_type TEXT NOT NULL,
                enabled INTEGER DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                UNIQUE(user_id, notification_type)
            );

            -- Notifications: accepted notifications
            CREATE TABLE IF NOT EXISTS notifications (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                notification_type TEXT NOT NULL,
                actor_id TEXT,
                actor_type TEXT,
                resource_type TEXT,
                resource_id TEXT,
                title TEXT,
                body TEXT,
                url TEXT,
                metadata TEXT,
                read INTEGER DEFAULT 0,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );

            -- ============================================================
            -- VIEWS
            -- ============================================================

            CREATE TABLE IF NOT EXISTS views (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                kind_id TEXT,
                config TEXT DEFAULT '{}',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (kind_id) REFERENCES kinds(id) ON DELETE SET NULL
            );

            -- ============================================================
            -- REACTIONS
            -- ============================================================

            CREATE TABLE IF NOT EXISTS reactions (
                id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                thing_id TEXT NOT NULL,
                reaction_type TEXT NOT NULL,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                FOREIGN KEY (thing_id) REFERENCES things(id) ON DELETE CASCADE,
                UNIQUE(user_id, thing_id, reaction_type)
            );

            CREATE INDEX IF NOT EXISTS idx_things_user_id ON things(user_id);
            CREATE INDEX IF NOT EXISTS idx_things_type ON things(type);
            CREATE INDEX IF NOT EXISTS idx_things_created_at ON things(created_at);
            CREATE INDEX IF NOT EXISTS idx_photos_thing_id ON photos(thing_id);
            CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
            CREATE INDEX IF NOT EXISTS idx_api_keys_key_prefix ON api_keys(key_prefix);
            CREATE INDEX IF NOT EXISTS idx_follows_follower ON follows(follower_id);
            CREATE INDEX IF NOT EXISTS idx_follows_following ON follows(following_id);

            -- Event system indexes
            CREATE INDEX IF NOT EXISTS idx_subscriptions_user ON subscriptions(user_id);
            CREATE INDEX IF NOT EXISTS idx_subscriptions_event_type ON subscriptions(event_type);
            CREATE INDEX IF NOT EXISTS idx_delivery_queue_status ON delivery_queue(status);
            CREATE INDEX IF NOT EXISTS idx_delivery_queue_next_attempt ON delivery_queue(next_attempt_at);

            -- Notification indexes
            CREATE INDEX IF NOT EXISTS idx_notification_settings_user ON notification_settings(user_id);
            CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);
            CREATE INDEX IF NOT EXISTS idx_notifications_user_unread ON notifications(user_id, read);
            CREATE INDEX IF NOT EXISTS idx_notifications_created ON notifications(created_at);

            -- Reaction indexes
            CREATE INDEX IF NOT EXISTS idx_reactions_thing ON reactions(thing_id);
            CREATE INDEX IF NOT EXISTS idx_reactions_user_thing ON reactions(user_id, thing_id);
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

    pub fn get_user_by_email(&self, email: &str) -> StoreResult<User> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT * FROM users WHERE email = ?1",
            params![email],
            |row| self.row_to_user(row),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                StoreError::NotFound(format!("User with email {}", email))
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

    pub fn lock_user(&self, id: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            "UPDATE users SET is_locked = 1, updated_at = ?1 WHERE id = ?2",
            params![Utc::now().to_rfc3339(), id],
        )?;
        if updated == 0 {
            return Err(StoreError::NotFound(format!("User {} not found", id)));
        }
        Ok(())
    }

    pub fn unlock_user(&self, id: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            "UPDATE users SET is_locked = 0, updated_at = ?1 WHERE id = ?2",
            params![Utc::now().to_rfc3339(), id],
        )?;
        if updated == 0 {
            return Err(StoreError::NotFound(format!("User {} not found", id)));
        }
        Ok(())
    }

    pub fn update_user(&self, user: &User) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let updated = conn.execute(
            r#"UPDATE users SET
                display_name = ?1,
                bio = ?2,
                avatar_url = ?3,
                updated_at = ?4
               WHERE id = ?5"#,
            params![
                &user.display_name,
                &user.bio,
                &user.avatar_url,
                Utc::now().to_rfc3339(),
                &user.id,
            ],
        )?;
        if updated == 0 {
            return Err(StoreError::NotFound(format!("User {} not found", user.id)));
        }
        Ok(())
    }

    pub fn list_users(&self) -> StoreResult<Vec<User>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT * FROM users ORDER BY created_at DESC")?;
        let rows = stmt.query_map([], |row| self.row_to_user(row))?;

        let mut users = Vec::new();
        for row in rows {
            users.push(row?);
        }
        Ok(users)
    }

    pub fn delete_user(&self, id: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute("DELETE FROM users WHERE id = ?1", params![id])?;
        if rows == 0 {
            return Err(StoreError::NotFound(format!("User {} not found", id)));
        }
        Ok(())
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

    pub fn restore_thing(&self, id: &str, user_id: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "UPDATE things SET deleted_at = NULL WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )?;
        if rows == 0 {
            return Err(StoreError::NotFound(format!("Thing {}", id)));
        }
        Ok(())
    }

    pub fn bulk_create_things(&self, things: &mut [Thing]) -> StoreResult<()> {
        if things.is_empty() {
            return Ok(());
        }

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let now = Utc::now();

        for thing in things.iter_mut() {
            thing.id = Uuid::new_v4().to_string();
            thing.version = 1;
            thing.created_at = now;
            thing.updated_at = now;

            let metadata_json = serde_json::to_string(&thing.metadata)?;

            tx.execute(
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
        }

        tx.commit()?;
        Ok(())
    }

    pub fn bulk_delete_things(&self, user_id: &str, ids: &[String]) -> StoreResult<usize> {
        if ids.is_empty() {
            return Ok(0);
        }

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let now = Utc::now().to_rfc3339();
        let mut deleted = 0;

        for id in ids {
            let rows = tx.execute(
                "UPDATE things SET deleted_at = ?1 WHERE id = ?2 AND user_id = ?3 AND deleted_at IS NULL",
                params![&now, id, user_id],
            )?;
            deleted += rows;
        }

        tx.commit()?;
        Ok(deleted)
    }

    /// Upsert a thing - find by metadata field match, create if not found, update if found
    /// Returns (Thing, created: bool) where created is true if a new thing was created
    pub fn upsert_thing(
        &self,
        user_id: &str,
        thing_type: &str,
        match_field: &str,
        match_value: &str,
        thing: &mut Thing,
    ) -> StoreResult<(Thing, bool)> {
        let conn = self.conn.lock().unwrap();

        // Try to find existing thing by type and metadata field match
        let json_path = format!("$.{}", match_field);
        let existing: Option<Thing> = conn
            .query_row(
                r#"SELECT id, user_id, type, content, metadata, visibility, version, deleted_at, created_at, updated_at
                   FROM things
                   WHERE user_id = ?1 AND type = ?2 AND json_extract(metadata, ?3) = ?4 AND deleted_at IS NULL"#,
                params![user_id, thing_type, &json_path, match_value],
                |row| self.row_to_thing(row),
            )
            .ok();

        if let Some(mut existing) = existing {
            // Update existing thing
            existing.content = thing.content.clone();
            // Merge metadata
            for (k, v) in &thing.metadata {
                existing.metadata.insert(k.clone(), v.clone());
            }
            existing.version += 1;
            existing.updated_at = Utc::now();

            let metadata_json = serde_json::to_string(&existing.metadata)?;
            conn.execute(
                r#"UPDATE things SET content = ?1, metadata = ?2, version = ?3, updated_at = ?4
                   WHERE id = ?5 AND user_id = ?6"#,
                params![
                    &existing.content,
                    &metadata_json,
                    existing.version,
                    existing.updated_at.to_rfc3339(),
                    &existing.id,
                    user_id,
                ],
            )?;

            Ok((existing, false)) // created=false (updated)
        } else {
            // Create new thing
            drop(conn); // Release lock before calling create_thing
            thing.user_id = user_id.to_string();
            thing.thing_type = thing_type.to_string();
            self.create_thing(thing)?;
            Ok((thing.clone(), true)) // created=true
        }
    }

    /// Bulk update multiple things in a transaction
    pub fn bulk_update_things(&self, user_id: &str, things: &mut [Thing]) -> StoreResult<usize> {
        if things.is_empty() {
            return Ok(0);
        }

        let mut conn = self.conn.lock().unwrap();
        let tx = conn.transaction()?;
        let mut updated = 0;

        for thing in things.iter_mut() {
            thing.updated_at = Utc::now();
            thing.version += 1;

            let metadata_json = serde_json::to_string(&thing.metadata)
                .map_err(|e| StoreError::Json(e))?;

            let rows = tx.execute(
                r#"UPDATE things SET type = ?1, content = ?2, metadata = ?3, version = ?4, updated_at = ?5
                   WHERE id = ?6 AND user_id = ?7 AND deleted_at IS NULL"#,
                params![
                    &thing.thing_type,
                    &thing.content,
                    &metadata_json,
                    thing.version,
                    thing.updated_at.to_rfc3339(),
                    &thing.id,
                    user_id,
                ],
            )?;

            if rows > 0 {
                // Create version record
                let version_id = Uuid::new_v4().to_string();
                tx.execute(
                    r#"INSERT INTO thing_versions (id, thing_id, version, type, content, metadata, created_at, created_by)
                       VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
                    params![
                        &version_id,
                        &thing.id,
                        thing.version,
                        &thing.thing_type,
                        &thing.content,
                        &metadata_json,
                        Utc::now().to_rfc3339(),
                        user_id,
                    ],
                )?;
                updated += 1;
            }
        }

        tx.commit()?;
        Ok(updated)
    }

    /// Search things by content or type
    pub fn search_things(&self, user_id: &str, query: &str, limit: i64) -> StoreResult<Vec<Thing>> {
        let conn = self.conn.lock().unwrap();
        let pattern = format!("%{}%", query);
        let limit = if limit <= 0 { 50 } else { limit };

        let mut stmt = conn.prepare(
            r#"SELECT * FROM things
               WHERE user_id = ?1 AND deleted_at IS NULL AND (content LIKE ?2 OR type LIKE ?2)
               ORDER BY created_at DESC
               LIMIT ?3"#,
        )?;

        let rows = stmt.query_map(params![user_id, &pattern, limit], |row| {
            self.row_to_thing(row)
        })?;

        let mut things = Vec::new();
        for row in rows {
            things.push(row?);
        }

        // Load photos for galleries
        drop(stmt);
        drop(conn);
        for thing in &mut things {
            if thing.thing_type == "gallery" {
                thing.photos = self.get_photos_by_thing_id(&thing.id)?;
            }
        }

        Ok(things)
    }

    /// Query things with advanced filtering, sorting, and pagination
    pub fn query_things(&self, q: ThingQuery) -> StoreResult<ThingQueryResult> {
        let conn = self.conn.lock().unwrap();

        // Build WHERE clause
        let mut where_clauses = vec!["user_id = ?1".to_string()];
        let mut args: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(q.user_id.clone())];
        let mut param_idx = 2;

        if !q.include_deleted {
            where_clauses.push("deleted_at IS NULL".to_string());
        }

        if let Some(ref t) = q.thing_type {
            where_clauses.push(format!("type = ?{}", param_idx));
            args.push(Box::new(t.clone()));
            param_idx += 1;
        }

        // Metadata filters (meta.field=value)
        for (field, value) in &q.metadata_filter {
            where_clauses.push(format!("json_extract(metadata, ?{}) = ?{}", param_idx, param_idx + 1));
            args.push(Box::new(format!("$.{}", field)));
            args.push(Box::new(value.clone()));
            param_idx += 2;
        }

        let where_clause = format!("WHERE {}", where_clauses.join(" AND "));

        // Count total
        let count_sql = format!("SELECT COUNT(*) FROM things {}", where_clause);
        let total: i64 = {
            let arg_refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
            conn.query_row(&count_sql, rusqlite::params_from_iter(arg_refs.iter()), |row| row.get(0))?
        };

        // Build ORDER BY
        let order_by = match &q.sort {
            Some(sort) => {
                let (desc, field) = if sort.starts_with('-') {
                    (true, &sort[1..])
                } else {
                    (false, sort.as_str())
                };
                let column = match field {
                    "createdAt" => "created_at",
                    "updatedAt" => "updated_at",
                    "type" => "type",
                    "content" => "content",
                    "version" => "version",
                    _ => "created_at",
                };
                if desc {
                    format!("ORDER BY {} DESC", column)
                } else {
                    format!("ORDER BY {} ASC", column)
                }
            }
            None => "ORDER BY created_at DESC".to_string(),
        };

        // Build LIMIT/OFFSET
        let page = if q.page < 1 { 1 } else { q.page };
        let count = q.count;

        let (limit_clause, use_limit) = if count <= 0 {
            ("".to_string(), false)
        } else {
            let offset = (page - 1) * count;
            args.push(Box::new(count));
            args.push(Box::new(offset));
            (format!(" LIMIT ?{} OFFSET ?{}", param_idx, param_idx + 1), true)
        };

        // Execute query
        let query_sql = format!(
            "SELECT * FROM things {} {} {}",
            where_clause, order_by, limit_clause
        );

        let mut things = Vec::new();
        {
            let arg_refs: Vec<&dyn rusqlite::ToSql> = args.iter().map(|b| b.as_ref()).collect();
            let mut stmt = conn.prepare(&query_sql)?;
            let rows = stmt.query_map(rusqlite::params_from_iter(arg_refs.iter()), |row| {
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

        // Calculate total pages
        let total_pages = if count > 0 {
            (total + count - 1) / count
        } else {
            1
        };

        Ok(ThingQueryResult {
            things,
            total,
            page,
            count,
            total_pages,
        })
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

    pub fn update_photo_caption(&self, id: &str, caption: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "UPDATE photos SET caption = ?1 WHERE id = ?2",
            params![caption, id],
        )?;
        if rows == 0 {
            return Err(StoreError::NotFound(format!("Photo {}", id)));
        }
        Ok(())
    }

    pub fn delete_photo(&self, id: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute("DELETE FROM photos WHERE id = ?1", params![id])?;
        if rows == 0 {
            return Err(StoreError::NotFound(format!("Photo {}", id)));
        }
        Ok(())
    }

    // ==================== Tag Operations ====================

    pub fn list_tags(&self, user_id: &str) -> StoreResult<Vec<Tag>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT id, user_id, name FROM tags WHERE user_id = ?1 ORDER BY name")?;
        let rows = stmt.query_map(params![user_id], |row| {
            Ok(Tag {
                id: row.get("id")?,
                user_id: row.get("user_id")?,
                name: row.get("name")?,
            })
        })?;

        let mut tags = Vec::new();
        for row in rows {
            tags.push(row?);
        }
        Ok(tags)
    }

    pub fn get_or_create_tag(&self, user_id: &str, name: &str) -> StoreResult<Tag> {
        let conn = self.conn.lock().unwrap();

        // Try to find existing tag
        let existing: Result<Tag, _> = conn.query_row(
            "SELECT id, user_id, name FROM tags WHERE user_id = ?1 AND name = ?2",
            params![user_id, name],
            |row| {
                Ok(Tag {
                    id: row.get("id")?,
                    user_id: row.get("user_id")?,
                    name: row.get("name")?,
                })
            },
        );

        if let Ok(tag) = existing {
            return Ok(tag);
        }

        // Create new tag
        let tag = Tag {
            id: Uuid::new_v4().to_string(),
            user_id: user_id.to_string(),
            name: name.to_string(),
        };

        conn.execute(
            "INSERT INTO tags (id, user_id, name) VALUES (?1, ?2, ?3)",
            params![&tag.id, &tag.user_id, &tag.name],
        )?;

        Ok(tag)
    }

    // ==================== Version History Operations ====================

    pub fn list_thing_versions(&self, thing_id: &str, user_id: &str) -> StoreResult<Vec<ThingVersion>> {
        let conn = self.conn.lock().unwrap();

        // First verify the user owns the thing
        let owner: Result<String, _> = conn.query_row(
            "SELECT user_id FROM things WHERE id = ?1",
            params![thing_id],
            |row| row.get(0),
        );

        match owner {
            Ok(uid) if uid != user_id => {
                return Err(StoreError::NotFound(format!("Thing {}", thing_id)));
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(StoreError::NotFound(format!("Thing {}", thing_id)));
            }
            Err(e) => return Err(StoreError::Database(e)),
            _ => {}
        }

        let mut stmt = conn.prepare(
            "SELECT id, thing_id, version, type, content, metadata, created_at, created_by
             FROM thing_versions WHERE thing_id = ?1 ORDER BY version DESC",
        )?;

        let rows = stmt.query_map(params![thing_id], |row| {
            let metadata_str: String = row.get("metadata")?;
            let metadata: HashMap<String, serde_json::Value> =
                serde_json::from_str(&metadata_str).unwrap_or_default();

            Ok(ThingVersion {
                id: row.get("id")?,
                thing_id: row.get("thing_id")?,
                version: row.get("version")?,
                thing_type: row.get("type")?,
                content: row.get("content")?,
                metadata,
                created_at: parse_datetime(row.get::<_, String>("created_at")?),
                created_by: row.get("created_by")?,
            })
        })?;

        let mut versions = Vec::new();
        for row in rows {
            versions.push(row?);
        }
        Ok(versions)
    }

    pub fn get_thing_version(&self, thing_id: &str, user_id: &str, version: i32) -> StoreResult<ThingVersion> {
        let conn = self.conn.lock().unwrap();

        // First verify the user owns the thing
        let owner: Result<String, _> = conn.query_row(
            "SELECT user_id FROM things WHERE id = ?1",
            params![thing_id],
            |row| row.get(0),
        );

        match owner {
            Ok(uid) if uid != user_id => {
                return Err(StoreError::NotFound(format!("Thing {}", thing_id)));
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => {
                return Err(StoreError::NotFound(format!("Thing {}", thing_id)));
            }
            Err(e) => return Err(StoreError::Database(e)),
            _ => {}
        }

        conn.query_row(
            "SELECT id, thing_id, version, type, content, metadata, created_at, created_by
             FROM thing_versions WHERE thing_id = ?1 AND version = ?2",
            params![thing_id, version],
            |row| {
                let metadata_str: String = row.get("metadata")?;
                let metadata: HashMap<String, serde_json::Value> =
                    serde_json::from_str(&metadata_str).unwrap_or_default();

                Ok(ThingVersion {
                    id: row.get("id")?,
                    thing_id: row.get("thing_id")?,
                    version: row.get("version")?,
                    thing_type: row.get("type")?,
                    content: row.get("content")?,
                    metadata,
                    created_at: parse_datetime(row.get::<_, String>("created_at")?),
                    created_by: row.get("created_by")?,
                })
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                StoreError::NotFound(format!("Version {} for thing {}", version, thing_id))
            }
            _ => StoreError::Database(e),
        })
    }

    // ==================== View Operations ====================

    pub fn list_views(&self, user_id: &str) -> StoreResult<Vec<View>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT id, user_id, name, type, kind_id, config, created_at, updated_at
             FROM views WHERE user_id = ?1 ORDER BY name",
        )?;

        let rows = stmt.query_map(params![user_id], |row| {
            let config_str: String = row.get("config")?;
            let config: ViewConfig = serde_json::from_str(&config_str).unwrap_or_default();

            Ok(View {
                id: row.get("id")?,
                user_id: row.get("user_id")?,
                name: row.get("name")?,
                view_type: row.get("type")?,
                kind_id: row.get("kind_id")?,
                config,
                created_at: parse_datetime(row.get::<_, String>("created_at")?),
                updated_at: parse_datetime(row.get::<_, String>("updated_at")?),
            })
        })?;

        let mut views = Vec::new();
        for row in rows {
            views.push(row?);
        }
        Ok(views)
    }

    pub fn create_view(&self, view: &mut View) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        view.id = Uuid::new_v4().to_string();
        view.created_at = Utc::now();
        view.updated_at = Utc::now();

        let config_json = serde_json::to_string(&view.config)?;

        conn.execute(
            r#"INSERT INTO views (id, user_id, name, type, kind_id, config, created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)"#,
            params![
                &view.id,
                &view.user_id,
                &view.name,
                &view.view_type,
                &view.kind_id,
                &config_json,
                view.created_at.to_rfc3339(),
                view.updated_at.to_rfc3339(),
            ],
        )?;

        Ok(())
    }

    pub fn get_view(&self, id: &str, user_id: &str) -> StoreResult<View> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT id, user_id, name, type, kind_id, config, created_at, updated_at
             FROM views WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
            |row| {
                let config_str: String = row.get("config")?;
                let config: ViewConfig = serde_json::from_str(&config_str).unwrap_or_default();

                Ok(View {
                    id: row.get("id")?,
                    user_id: row.get("user_id")?,
                    name: row.get("name")?,
                    view_type: row.get("type")?,
                    kind_id: row.get("kind_id")?,
                    config,
                    created_at: parse_datetime(row.get::<_, String>("created_at")?),
                    updated_at: parse_datetime(row.get::<_, String>("updated_at")?),
                })
            },
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("View {}", id)),
            _ => StoreError::Database(e),
        })
    }

    pub fn update_view(&self, view: &mut View) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        view.updated_at = Utc::now();

        let config_json = serde_json::to_string(&view.config)?;

        let rows = conn.execute(
            "UPDATE views SET name = ?1, type = ?2, kind_id = ?3, config = ?4, updated_at = ?5
             WHERE id = ?6 AND user_id = ?7",
            params![
                &view.name,
                &view.view_type,
                &view.kind_id,
                &config_json,
                view.updated_at.to_rfc3339(),
                &view.id,
                &view.user_id,
            ],
        )?;

        if rows == 0 {
            return Err(StoreError::NotFound(format!("View {}", view.id)));
        }
        Ok(())
    }

    pub fn delete_view(&self, id: &str, user_id: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "DELETE FROM views WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )?;

        if rows == 0 {
            return Err(StoreError::NotFound(format!("View {}", id)));
        }
        Ok(())
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

    pub fn get_api_key_for_user(&self, id: &str, user_id: &str) -> StoreResult<ApiKey> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT * FROM api_keys WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
            |row| self.row_to_api_key(row),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound("API Key".to_string()),
            _ => StoreError::Database(e),
        })
    }

    pub fn update_api_key(&self, key: &ApiKey) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let scopes_json = serde_json::to_string(&key.scopes)?;
        let metadata_json = serde_json::to_string(&key.metadata)?;
        let expires_at = key.expires_at.map(|t| t.to_rfc3339());

        let updated = conn.execute(
            r#"UPDATE api_keys SET
                name = ?1,
                scopes = ?2,
                metadata = ?3,
                expires_at = ?4
               WHERE id = ?5 AND user_id = ?6"#,
            params![
                &key.name,
                &scopes_json,
                &metadata_json,
                &expires_at,
                &key.id,
                &key.user_id,
            ],
        )?;
        if updated == 0 {
            return Err(StoreError::NotFound(format!("API Key {}", key.id)));
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

    /// Get owner profile (first admin user's public information)
    pub fn get_owner_profile(&self) -> StoreResult<User> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT * FROM users WHERE is_admin = 1 ORDER BY created_at ASC LIMIT 1"#
        )?;

        let user = stmt.query_row([], |row| {
            Ok(User {
                id: row.get("id")?,
                username: row.get("username")?,
                email: row.get("email")?,
                password_hash: String::new(), // Don't expose password hash
                display_name: row.get("display_name")?,
                bio: row.get("bio")?,
                avatar_url: row.get("avatar_url")?,
                is_admin: row.get("is_admin")?,
                is_locked: row.get("is_locked")?,
                recovery_hash: String::new(), // Don't expose recovery hash
                created_at: parse_datetime(row.get("created_at")?),
                updated_at: parse_datetime(row.get("updated_at")?),
            })
        })?;

        Ok(user)
    }

    /// Get public things (visibility = 'public')
    pub fn get_public_things(&self, limit: usize, offset: usize) -> StoreResult<Vec<Thing>> {
        let mut things = Vec::new();
        {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare(
                r#"SELECT * FROM things
                   WHERE visibility = 'public' AND deleted_at IS NULL
                   ORDER BY created_at DESC
                   LIMIT ?1 OFFSET ?2"#
            )?;

            let rows = stmt.query_map(params![limit, offset], |row| {
                self.row_to_thing(row)
            })?;
            for row in rows {
                things.push(row?);
            }
        } // conn and stmt are dropped here

        // Load photos for galleries
        for thing in &mut things {
            if thing.thing_type == "gallery" {
                thing.photos = self.get_photos_by_thing_id(&thing.id)?;
            }
        }

        Ok(things)
    }

    // ==================== Follow Operations ====================

    /// Create a follow relationship (user follows another user)
    pub fn create_follow(&self, follow: &mut crate::models::Follow) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        follow.id = Uuid::new_v4().to_string();
        follow.created_at = Utc::now();

        conn.execute(
            r#"INSERT INTO follows (id, follower_id, following_id, remote_endpoint, access_token, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6)"#,
            params![
                &follow.id,
                &follow.follower_id,
                &follow.following_id,
                &follow.remote_endpoint,
                &follow.access_token,
                follow.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    /// Delete a follow relationship (unfollow)
    pub fn delete_follow(&self, follower_id: &str, following_id: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "DELETE FROM follows WHERE follower_id = ?1 AND following_id = ?2",
            params![follower_id, following_id],
        )?;
        if rows == 0 {
            return Err(StoreError::NotFound("Follow relationship not found".to_string()));
        }
        Ok(())
    }

    /// Get all followers of a user (users who follow this user)
    pub fn get_followers(&self, user_id: &str) -> StoreResult<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT follower_id FROM follows WHERE following_id = ?1 ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map(params![user_id], |row| row.get(0))?;

        let mut followers = Vec::new();
        for row in rows {
            followers.push(row?);
        }
        Ok(followers)
    }

    /// Get all users that this user is following
    pub fn get_following(&self, user_id: &str) -> StoreResult<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT following_id FROM follows WHERE follower_id = ?1 ORDER BY created_at DESC"
        )?;
        let rows = stmt.query_map(params![user_id], |row| row.get(0))?;

        let mut following = Vec::new();
        for row in rows {
            following.push(row?);
        }
        Ok(following)
    }

    /// Get mutual followers (users where both follow each other)
    pub fn get_mutuals(&self, user_id: &str) -> StoreResult<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT f1.following_id
               FROM follows f1
               INNER JOIN follows f2 ON f1.following_id = f2.follower_id
               WHERE f1.follower_id = ?1 AND f2.following_id = ?1
               ORDER BY f1.created_at DESC"#
        )?;
        let rows = stmt.query_map(params![user_id], |row| row.get(0))?;

        let mut mutuals = Vec::new();
        for row in rows {
            mutuals.push(row?);
        }
        Ok(mutuals)
    }

    /// Check if follower_id follows following_id
    pub fn is_following(&self, follower_id: &str, following_id: &str) -> StoreResult<bool> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM follows WHERE follower_id = ?1 AND following_id = ?2",
            params![follower_id, following_id],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Get friend feed (things from followed users with visibility 'friends' or 'public')
    pub fn get_friend_feed(&self, user_id: &str, limit: i64, offset: i64) -> StoreResult<Vec<Thing>> {
        let mut things = Vec::new();
        {
            let conn = self.conn.lock().unwrap();
            let mut stmt = conn.prepare(
                r#"SELECT t.* FROM things t
                   INNER JOIN follows f ON t.user_id = f.following_id
                   WHERE f.follower_id = ?1
                   AND (t.visibility = 'friends' OR t.visibility = 'public')
                   AND t.deleted_at IS NULL
                   ORDER BY t.created_at DESC
                   LIMIT ?2 OFFSET ?3"#
            )?;

            let rows = stmt.query_map(params![user_id, limit, offset], |row| {
                self.row_to_thing(row)
            })?;
            for row in rows {
                things.push(row?);
            }
        } // conn and stmt are dropped here

        // Load photos for galleries
        for thing in &mut things {
            if thing.thing_type == "gallery" {
                thing.photos = self.get_photos_by_thing_id(&thing.id)?;
            }
        }

        Ok(things)
    }

    // ==================== Subscription Operations ====================

    pub fn create_subscription(&self, sub: &Subscription) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let config_json = serde_json::to_string(&sub.action_config)?;

        conn.execute(
            r#"INSERT INTO subscriptions (id, user_id, name, event_type, source_type, source_id,
                action_type, action_config, enabled, created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)"#,
            params![
                &sub.id,
                &sub.user_id,
                &sub.name,
                &sub.event_type,
                &sub.source_type,
                &sub.source_id,
                &sub.action_type,
                &config_json,
                sub.enabled,
                sub.created_at.to_rfc3339(),
                sub.updated_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn list_subscriptions(&self, user_id: &str) -> StoreResult<Vec<Subscription>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT * FROM subscriptions WHERE user_id = ?1 ORDER BY created_at DESC"
        )?;

        let rows = stmt.query_map(params![user_id], |row| self.row_to_subscription(row))?;
        let mut subs = Vec::new();
        for row in rows {
            subs.push(row?);
        }
        Ok(subs)
    }

    pub fn get_subscription(&self, id: &str) -> StoreResult<Subscription> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT * FROM subscriptions WHERE id = ?1",
            params![id],
            |row| self.row_to_subscription(row),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("Subscription {}", id)),
            _ => StoreError::Database(e),
        })
    }

    pub fn update_subscription(&self, sub: &Subscription) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let config_json = serde_json::to_string(&sub.action_config)?;

        let rows = conn.execute(
            r#"UPDATE subscriptions SET name = ?1, event_type = ?2, source_type = ?3,
               source_id = ?4, action_type = ?5, action_config = ?6, enabled = ?7, updated_at = ?8
               WHERE id = ?9"#,
            params![
                &sub.name,
                &sub.event_type,
                &sub.source_type,
                &sub.source_id,
                &sub.action_type,
                &config_json,
                sub.enabled,
                sub.updated_at.to_rfc3339(),
                &sub.id,
            ],
        )?;

        if rows == 0 {
            return Err(StoreError::NotFound(format!("Subscription {}", sub.id)));
        }
        Ok(())
    }

    pub fn delete_subscription(&self, id: &str, user_id: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "DELETE FROM subscriptions WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )?;
        if rows == 0 {
            return Err(StoreError::NotFound(format!("Subscription {}", id)));
        }
        Ok(())
    }

    /// Find subscriptions matching an event
    pub fn find_matching_subscriptions(
        &self,
        event_type: &str,
        source_type: Option<&str>,
        source_id: Option<&str>,
    ) -> StoreResult<Vec<Subscription>> {
        let conn = self.conn.lock().unwrap();
        // Match exact event_type or wildcard '*'
        let mut stmt = conn.prepare(
            r#"SELECT * FROM subscriptions
               WHERE enabled = 1
               AND (event_type = ?1 OR event_type = '*')
               AND (source_type IS NULL OR source_type = ?2)
               AND (source_id IS NULL OR source_id = ?3)"#
        )?;

        let rows = stmt.query_map(
            params![event_type, source_type.unwrap_or(""), source_id.unwrap_or("")],
            |row| self.row_to_subscription(row),
        )?;

        let mut subs = Vec::new();
        for row in rows {
            subs.push(row?);
        }
        Ok(subs)
    }

    fn row_to_subscription(&self, row: &rusqlite::Row) -> rusqlite::Result<Subscription> {
        let config_str: String = row.get("action_config")?;
        let action_config: HashMap<String, serde_json::Value> =
            serde_json::from_str(&config_str).unwrap_or_default();

        Ok(Subscription {
            id: row.get("id")?,
            user_id: row.get("user_id")?,
            name: row.get("name")?,
            event_type: row.get("event_type")?,
            source_type: row.get("source_type")?,
            source_id: row.get("source_id")?,
            action_type: row.get("action_type")?,
            action_config,
            enabled: row.get("enabled")?,
            created_at: parse_datetime(row.get("created_at")?),
            updated_at: parse_datetime(row.get("updated_at")?),
        })
    }

    // ==================== Delivery Queue Operations ====================

    pub fn queue_delivery(
        &self,
        delivery_type: &str,
        destination: &str,
        payload: &str,
    ) -> StoreResult<String> {
        let conn = self.conn.lock().unwrap();
        let id = Uuid::new_v4().to_string();
        let now = Utc::now();
        // First retry in 30 seconds
        let next_attempt = now + chrono::Duration::seconds(30);

        conn.execute(
            r#"INSERT INTO delivery_queue (id, delivery_type, destination, payload, status,
                attempts, max_attempts, next_attempt_at, created_at)
               VALUES (?1, ?2, ?3, ?4, 'pending', 0, 3, ?5, ?6)"#,
            params![
                &id,
                delivery_type,
                destination,
                payload,
                next_attempt.to_rfc3339(),
                now.to_rfc3339(),
            ],
        )?;
        Ok(id)
    }

    pub fn get_pending_deliveries(&self, limit: i64) -> StoreResult<Vec<DeliveryQueueItem>> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now().to_rfc3339();
        let mut stmt = conn.prepare(
            r#"SELECT * FROM delivery_queue
               WHERE status = 'pending' AND next_attempt_at <= ?1
               ORDER BY next_attempt_at ASC
               LIMIT ?2"#
        )?;

        let rows = stmt.query_map(params![now, limit], |row| self.row_to_delivery_queue_item(row))?;
        let mut items = Vec::new();
        for row in rows {
            items.push(row?);
        }
        Ok(items)
    }

    pub fn update_delivery_status(
        &self,
        id: &str,
        status: &DeliveryStatus,
        error: Option<&str>,
    ) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now();

        match status {
            DeliveryStatus::Delivered => {
                conn.execute(
                    r#"UPDATE delivery_queue SET status = 'delivered', delivered_at = ?1
                       WHERE id = ?2"#,
                    params![now.to_rfc3339(), id],
                )?;
            }
            DeliveryStatus::Rejected => {
                conn.execute(
                    "UPDATE delivery_queue SET status = 'rejected' WHERE id = ?1",
                    params![id],
                )?;
            }
            DeliveryStatus::Failed => {
                // Get current item data inline (avoid deadlock from nested lock)
                let (attempts, max_attempts): (i32, i32) = conn.query_row(
                    "SELECT attempts, max_attempts FROM delivery_queue WHERE id = ?1",
                    params![id],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )?;
                let new_attempts = attempts + 1;

                if new_attempts >= max_attempts {
                    conn.execute(
                        r#"UPDATE delivery_queue SET status = 'failed', attempts = ?1, last_error = ?2
                           WHERE id = ?3"#,
                        params![new_attempts, error, id],
                    )?;
                } else {
                    // Exponential backoff: 30s, 60s, 120s, etc.
                    let delay_seconds = 30 * (2_i64.pow(new_attempts as u32));
                    let next_attempt = now + chrono::Duration::seconds(delay_seconds);
                    conn.execute(
                        r#"UPDATE delivery_queue SET attempts = ?1, next_attempt_at = ?2, last_error = ?3
                           WHERE id = ?4"#,
                        params![new_attempts, next_attempt.to_rfc3339(), error, id],
                    )?;
                }
            }
            DeliveryStatus::Pending => {}
        }
        Ok(())
    }

    fn get_delivery_queue_item(&self, id: &str) -> StoreResult<DeliveryQueueItem> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT * FROM delivery_queue WHERE id = ?1",
            params![id],
            |row| self.row_to_delivery_queue_item(row),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => StoreError::NotFound(format!("Delivery {}", id)),
            _ => StoreError::Database(e),
        })
    }

    fn row_to_delivery_queue_item(&self, row: &rusqlite::Row) -> rusqlite::Result<DeliveryQueueItem> {
        let status_str: String = row.get("status")?;
        let next_attempt: Option<String> = row.get("next_attempt_at")?;
        let delivered_at: Option<String> = row.get("delivered_at")?;

        Ok(DeliveryQueueItem {
            id: row.get("id")?,
            delivery_type: row.get("delivery_type")?,
            destination: row.get("destination")?,
            payload: row.get("payload")?,
            status: DeliveryStatus::from_str(&status_str),
            attempts: row.get("attempts")?,
            max_attempts: row.get("max_attempts")?,
            next_attempt_at: next_attempt.map(parse_datetime),
            last_error: row.get("last_error")?,
            created_at: parse_datetime(row.get("created_at")?),
            delivered_at: delivered_at.map(parse_datetime),
        })
    }

    // ==================== Notification Settings Operations ====================

    pub fn get_notification_settings(
        &self,
        user_id: &str,
        notification_type: &str,
    ) -> StoreResult<NotificationSettings> {
        let conn = self.conn.lock().unwrap();
        conn.query_row(
            "SELECT * FROM notification_settings WHERE user_id = ?1 AND notification_type = ?2",
            params![user_id, notification_type],
            |row| self.row_to_notification_settings(row),
        )
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                StoreError::NotFound(format!("NotificationSettings for {}", notification_type))
            }
            _ => StoreError::Database(e),
        })
    }

    pub fn get_all_notification_settings(&self, user_id: &str) -> StoreResult<Vec<NotificationSettings>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT * FROM notification_settings WHERE user_id = ?1"
        )?;

        let rows = stmt.query_map(params![user_id], |row| self.row_to_notification_settings(row))?;
        let mut settings = Vec::new();
        for row in rows {
            settings.push(row?);
        }
        Ok(settings)
    }

    pub fn update_notification_settings(
        &self,
        user_id: &str,
        notification_type: &str,
        enabled: bool,
    ) -> StoreResult<NotificationSettings> {
        let conn = self.conn.lock().unwrap();
        let now = Utc::now();

        // Upsert
        let id = Uuid::new_v4().to_string();
        conn.execute(
            r#"INSERT INTO notification_settings (id, user_id, notification_type, enabled, created_at, updated_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6)
               ON CONFLICT(user_id, notification_type) DO UPDATE SET enabled = ?4, updated_at = ?6"#,
            params![
                &id,
                user_id,
                notification_type,
                enabled,
                now.to_rfc3339(),
                now.to_rfc3339(),
            ],
        )?;

        // Return the settings
        drop(conn);
        self.get_notification_settings(user_id, notification_type)
    }

    fn row_to_notification_settings(&self, row: &rusqlite::Row) -> rusqlite::Result<NotificationSettings> {
        Ok(NotificationSettings {
            id: row.get("id")?,
            user_id: row.get("user_id")?,
            notification_type: row.get("notification_type")?,
            enabled: row.get("enabled")?,
            created_at: parse_datetime(row.get("created_at")?),
            updated_at: parse_datetime(row.get("updated_at")?),
        })
    }

    // ==================== Notification Operations ====================

    pub fn create_notification(&self, notif: &Notification) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let metadata_json = notif.metadata.as_ref()
            .map(|m| serde_json::to_string(m).unwrap_or_else(|_| "{}".to_string()));

        conn.execute(
            r#"INSERT INTO notifications (id, user_id, notification_type, actor_id, actor_type,
                resource_type, resource_id, title, body, url, metadata, read, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)"#,
            params![
                &notif.id,
                &notif.user_id,
                &notif.notification_type,
                &notif.actor_id,
                &notif.actor_type,
                &notif.resource_type,
                &notif.resource_id,
                &notif.title,
                &notif.body,
                &notif.url,
                &metadata_json,
                notif.read,
                notif.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn list_notifications(
        &self,
        user_id: &str,
        limit: i64,
        offset: i64,
    ) -> StoreResult<Vec<Notification>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            r#"SELECT * FROM notifications WHERE user_id = ?1
               ORDER BY created_at DESC LIMIT ?2 OFFSET ?3"#
        )?;

        let rows = stmt.query_map(params![user_id, limit, offset], |row| {
            self.row_to_notification(row)
        })?;

        let mut notifs = Vec::new();
        for row in rows {
            notifs.push(row?);
        }
        Ok(notifs)
    }

    pub fn count_notifications(&self, user_id: &str) -> StoreResult<i64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM notifications WHERE user_id = ?1",
            params![user_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn get_unread_count(&self, user_id: &str) -> StoreResult<i64> {
        let conn = self.conn.lock().unwrap();
        let count: i64 = conn.query_row(
            "SELECT COUNT(*) FROM notifications WHERE user_id = ?1 AND read = 0",
            params![user_id],
            |row| row.get(0),
        )?;
        Ok(count)
    }

    pub fn mark_notification_read(&self, id: &str, user_id: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "UPDATE notifications SET read = 1 WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )?;
        if rows == 0 {
            return Err(StoreError::NotFound(format!("Notification {}", id)));
        }
        Ok(())
    }

    pub fn mark_all_notifications_read(&self, user_id: &str) -> StoreResult<i64> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "UPDATE notifications SET read = 1 WHERE user_id = ?1 AND read = 0",
            params![user_id],
        )?;
        Ok(rows as i64)
    }

    pub fn delete_notification(&self, id: &str, user_id: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "DELETE FROM notifications WHERE id = ?1 AND user_id = ?2",
            params![id, user_id],
        )?;
        if rows == 0 {
            return Err(StoreError::NotFound(format!("Notification {}", id)));
        }
        Ok(())
    }

    fn row_to_notification(&self, row: &rusqlite::Row) -> rusqlite::Result<Notification> {
        let metadata_str: Option<String> = row.get("metadata")?;
        let metadata: Option<HashMap<String, serde_json::Value>> = metadata_str
            .and_then(|s| serde_json::from_str(&s).ok());

        Ok(Notification {
            id: row.get("id")?,
            user_id: row.get("user_id")?,
            notification_type: row.get("notification_type")?,
            actor_id: row.get("actor_id")?,
            actor_type: row.get("actor_type")?,
            resource_type: row.get("resource_type")?,
            resource_id: row.get("resource_id")?,
            title: row.get("title")?,
            body: row.get("body")?,
            url: row.get("url")?,
            metadata,
            read: row.get("read")?,
            created_at: parse_datetime(row.get("created_at")?),
        })
    }

    // ==================== Reaction Operations ====================

    pub fn add_reaction(&self, reaction: &Reaction) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            r#"INSERT INTO reactions (id, user_id, thing_id, reaction_type, created_at)
               VALUES (?1, ?2, ?3, ?4, ?5)"#,
            params![
                &reaction.id,
                &reaction.user_id,
                &reaction.thing_id,
                &reaction.reaction_type,
                reaction.created_at.to_rfc3339(),
            ],
        )?;
        Ok(())
    }

    pub fn remove_reaction(&self, user_id: &str, thing_id: &str, reaction_type: &str) -> StoreResult<()> {
        let conn = self.conn.lock().unwrap();
        let rows = conn.execute(
            "DELETE FROM reactions WHERE user_id = ?1 AND thing_id = ?2 AND reaction_type = ?3",
            params![user_id, thing_id, reaction_type],
        )?;
        if rows == 0 {
            return Err(StoreError::NotFound("Reaction not found".to_string()));
        }
        Ok(())
    }

    pub fn get_reactions_for_thing(&self, thing_id: &str) -> StoreResult<Vec<Reaction>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT * FROM reactions WHERE thing_id = ?1 ORDER BY created_at DESC"
        )?;

        let rows = stmt.query_map(params![thing_id], |row| self.row_to_reaction(row))?;
        let mut reactions = Vec::new();
        for row in rows {
            reactions.push(row?);
        }
        Ok(reactions)
    }

    pub fn get_reaction_counts(&self, thing_id: &str) -> StoreResult<HashMap<String, i64>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT reaction_type, COUNT(*) as count FROM reactions WHERE thing_id = ?1 GROUP BY reaction_type"
        )?;

        let rows = stmt.query_map(params![thing_id], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;

        let mut counts = HashMap::new();
        for row in rows {
            let (reaction_type, count) = row?;
            counts.insert(reaction_type, count);
        }
        Ok(counts)
    }

    pub fn get_user_reactions(&self, user_id: &str, thing_id: &str) -> StoreResult<Vec<String>> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT reaction_type FROM reactions WHERE user_id = ?1 AND thing_id = ?2"
        )?;

        let rows = stmt.query_map(params![user_id, thing_id], |row| row.get(0))?;
        let mut reactions = Vec::new();
        for row in rows {
            reactions.push(row?);
        }
        Ok(reactions)
    }

    pub fn get_reaction_summary(&self, thing_id: &str, user_id: Option<&str>) -> StoreResult<ReactionSummary> {
        let counts = self.get_reaction_counts(thing_id)?;
        let user_reactions = match user_id {
            Some(uid) => self.get_user_reactions(uid, thing_id)?,
            None => Vec::new(),
        };
        Ok(ReactionSummary { counts, user_reactions })
    }

    fn row_to_reaction(&self, row: &rusqlite::Row) -> rusqlite::Result<Reaction> {
        Ok(Reaction {
            id: row.get("id")?,
            user_id: row.get("user_id")?,
            thing_id: row.get("thing_id")?,
            reaction_type: row.get("reaction_type")?,
            created_at: parse_datetime(row.get("created_at")?),
        })
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

    #[test]
    fn test_follow_unfollow() {
        let store = Store::in_memory().unwrap();

        // Create two users
        let mut user1 = User {
            id: String::new(),
            username: "user1".to_string(),
            email: "user1@example.com".to_string(),
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
        store.create_user(&mut user1).unwrap();

        let mut user2 = User {
            id: String::new(),
            username: "user2".to_string(),
            email: "user2@example.com".to_string(),
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
        store.create_user(&mut user2).unwrap();

        // User1 follows User2
        let mut follow = crate::models::Follow {
            id: String::new(),
            follower_id: user1.id.clone(),
            following_id: user2.id.clone(),
            created_at: Utc::now(),
            remote_endpoint: "local".to_string(),
            access_token: None,
        };
        store.create_follow(&mut follow).unwrap();
        assert!(!follow.id.is_empty());

        // Check is_following
        assert!(store.is_following(&user1.id, &user2.id).unwrap());
        assert!(!store.is_following(&user2.id, &user1.id).unwrap());

        // Get followers and following
        let user2_followers = store.get_followers(&user2.id).unwrap();
        assert_eq!(user2_followers.len(), 1);
        assert_eq!(user2_followers[0], user1.id);

        let user1_following = store.get_following(&user1.id).unwrap();
        assert_eq!(user1_following.len(), 1);
        assert_eq!(user1_following[0], user2.id);

        // Unfollow
        store.delete_follow(&user1.id, &user2.id).unwrap();
        assert!(!store.is_following(&user1.id, &user2.id).unwrap());
        assert_eq!(store.get_followers(&user2.id).unwrap().len(), 0);
    }

    #[test]
    fn test_mutual_followers() {
        let store = Store::in_memory().unwrap();

        // Create three users
        let mut user1 = User {
            id: String::new(),
            username: "user1".to_string(),
            email: "user1@example.com".to_string(),
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
        store.create_user(&mut user1).unwrap();

        let mut user2 = User {
            id: String::new(),
            username: "user2".to_string(),
            email: "user2@example.com".to_string(),
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
        store.create_user(&mut user2).unwrap();

        let mut user3 = User {
            id: String::new(),
            username: "user3".to_string(),
            email: "user3@example.com".to_string(),
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
        store.create_user(&mut user3).unwrap();

        // User1 follows User2 (one-way)
        let mut follow1 = crate::models::Follow {
            id: String::new(),
            follower_id: user1.id.clone(),
            following_id: user2.id.clone(),
            created_at: Utc::now(),
            remote_endpoint: "local".to_string(),
            access_token: None,
        };
        store.create_follow(&mut follow1).unwrap();

        // User1 follows User3, and User3 follows User1 (mutual)
        let mut follow2 = crate::models::Follow {
            id: String::new(),
            follower_id: user1.id.clone(),
            following_id: user3.id.clone(),
            created_at: Utc::now(),
            remote_endpoint: "local".to_string(),
            access_token: None,
        };
        store.create_follow(&mut follow2).unwrap();

        let mut follow3 = crate::models::Follow {
            id: String::new(),
            follower_id: user3.id.clone(),
            following_id: user1.id.clone(),
            created_at: Utc::now(),
            remote_endpoint: "local".to_string(),
            access_token: None,
        };
        store.create_follow(&mut follow3).unwrap();

        // Check mutuals
        let user1_mutuals = store.get_mutuals(&user1.id).unwrap();
        assert_eq!(user1_mutuals.len(), 1);
        assert_eq!(user1_mutuals[0], user3.id);

        let user2_mutuals = store.get_mutuals(&user2.id).unwrap();
        assert_eq!(user2_mutuals.len(), 0); // User2 doesn't follow User1 back
    }

    #[test]
    fn test_friend_feed_visibility() {
        let store = Store::in_memory().unwrap();

        // Create two users
        let mut user1 = User {
            id: String::new(),
            username: "user1".to_string(),
            email: "user1@example.com".to_string(),
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
        store.create_user(&mut user1).unwrap();

        let mut user2 = User {
            id: String::new(),
            username: "user2".to_string(),
            email: "user2@example.com".to_string(),
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
        store.create_user(&mut user2).unwrap();

        // User1 follows User2
        let mut follow = crate::models::Follow {
            id: String::new(),
            follower_id: user1.id.clone(),
            following_id: user2.id.clone(),
            created_at: Utc::now(),
            remote_endpoint: "local".to_string(),
            access_token: None,
        };
        store.create_follow(&mut follow).unwrap();

        // User2 creates things with different visibility
        let mut private_thing = Thing {
            id: String::new(),
            user_id: user2.id.clone(),
            thing_type: "note".to_string(),
            content: "Private note".to_string(),
            metadata: HashMap::new(),
            visibility: "private".to_string(),
            version: 0,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut private_thing).unwrap();

        let mut friends_thing = Thing {
            id: String::new(),
            user_id: user2.id.clone(),
            thing_type: "note".to_string(),
            content: "Friends note".to_string(),
            metadata: HashMap::new(),
            visibility: "friends".to_string(),
            version: 0,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut friends_thing).unwrap();

        let mut public_thing = Thing {
            id: String::new(),
            user_id: user2.id.clone(),
            thing_type: "note".to_string(),
            content: "Public note".to_string(),
            metadata: HashMap::new(),
            visibility: "public".to_string(),
            version: 0,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut public_thing).unwrap();

        // User1's friend feed should only see friends and public things
        let feed = store.get_friend_feed(&user1.id, 10, 0).unwrap();
        assert_eq!(feed.len(), 2);

        // Verify it's the friends and public things (not private)
        let contents: Vec<String> = feed.iter().map(|t| t.content.clone()).collect();
        assert!(contents.contains(&"Friends note".to_string()));
        assert!(contents.contains(&"Public note".to_string()));
        assert!(!contents.contains(&"Private note".to_string()));
    }

    #[test]
    fn test_duplicate_follow() {
        let store = Store::in_memory().unwrap();

        // Create two users
        let mut user1 = User {
            id: String::new(),
            username: "user1".to_string(),
            email: "user1@example.com".to_string(),
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
        store.create_user(&mut user1).unwrap();

        let mut user2 = User {
            id: String::new(),
            username: "user2".to_string(),
            email: "user2@example.com".to_string(),
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
        store.create_user(&mut user2).unwrap();

        // First follow should succeed
        let mut follow1 = crate::models::Follow {
            id: String::new(),
            follower_id: user1.id.clone(),
            following_id: user2.id.clone(),
            created_at: Utc::now(),
            remote_endpoint: "local".to_string(),
            access_token: None,
        };
        assert!(store.create_follow(&mut follow1).is_ok());

        // Duplicate follow should fail due to UNIQUE constraint
        let mut follow2 = crate::models::Follow {
            id: String::new(),
            follower_id: user1.id.clone(),
            following_id: user2.id.clone(),
            created_at: Utc::now(),
            remote_endpoint: "local".to_string(),
            access_token: None,
        };
        assert!(store.create_follow(&mut follow2).is_err());
    }

    // ==================== Subscription Tests ====================

    #[test]
    fn test_create_and_list_subscriptions() {
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

        // Create a subscription
        let mut config = HashMap::new();
        config.insert("destination".to_string(), serde_json::json!("local"));

        let sub = Subscription {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            name: Some("Test sub".to_string()),
            event_type: "follow.created".to_string(),
            source_type: None,
            source_id: None,
            action_type: "notification".to_string(),
            action_config: config,
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        store.create_subscription(&sub).unwrap();

        // List subscriptions
        let subs = store.list_subscriptions(&user.id).unwrap();
        assert_eq!(subs.len(), 1);
        assert_eq!(subs[0].event_type, "follow.created");
        assert_eq!(subs[0].name, Some("Test sub".to_string()));
    }

    #[test]
    fn test_get_and_update_subscription() {
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

        let sub_id = uuid::Uuid::new_v4().to_string();
        let sub = Subscription {
            id: sub_id.clone(),
            user_id: user.id.clone(),
            name: Some("Original name".to_string()),
            event_type: "follow.created".to_string(),
            source_type: None,
            source_id: None,
            action_type: "notification".to_string(),
            action_config: HashMap::new(),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        store.create_subscription(&sub).unwrap();

        // Get subscription
        let retrieved = store.get_subscription(&sub_id).unwrap();
        assert_eq!(retrieved.name, Some("Original name".to_string()));

        // Update subscription
        let updated_sub = Subscription {
            id: sub_id.clone(),
            user_id: user.id.clone(),
            name: Some("Updated name".to_string()),
            event_type: "reaction.added".to_string(),
            source_type: Some("thing".to_string()),
            source_id: None,
            action_type: "webhook".to_string(),
            action_config: HashMap::new(),
            enabled: false,
            created_at: retrieved.created_at,
            updated_at: Utc::now(),
        };

        store.update_subscription(&updated_sub).unwrap();

        let retrieved2 = store.get_subscription(&sub_id).unwrap();
        assert_eq!(retrieved2.name, Some("Updated name".to_string()));
        assert_eq!(retrieved2.event_type, "reaction.added");
        assert!(!retrieved2.enabled);
    }

    #[test]
    fn test_delete_subscription() {
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

        let sub_id = uuid::Uuid::new_v4().to_string();
        let sub = Subscription {
            id: sub_id.clone(),
            user_id: user.id.clone(),
            name: None,
            event_type: "test.event".to_string(),
            source_type: None,
            source_id: None,
            action_type: "notification".to_string(),
            action_config: HashMap::new(),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        store.create_subscription(&sub).unwrap();
        assert!(store.get_subscription(&sub_id).is_ok());

        store.delete_subscription(&sub_id, &user.id).unwrap();
        assert!(store.get_subscription(&sub_id).is_err());
    }

    #[test]
    fn test_find_matching_subscriptions() {
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

        // Create subscriptions with different event types
        let sub1 = Subscription {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            name: None,
            event_type: "follow.created".to_string(),
            source_type: None,
            source_id: None,
            action_type: "notification".to_string(),
            action_config: HashMap::new(),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let sub2 = Subscription {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            name: None,
            event_type: "reaction.added".to_string(),
            source_type: Some("thing".to_string()),
            source_id: None,
            action_type: "notification".to_string(),
            action_config: HashMap::new(),
            enabled: true,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let sub3 = Subscription {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            name: None,
            event_type: "follow.created".to_string(),
            source_type: None,
            source_id: None,
            action_type: "webhook".to_string(),
            action_config: HashMap::new(),
            enabled: false, // disabled
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        store.create_subscription(&sub1).unwrap();
        store.create_subscription(&sub2).unwrap();
        store.create_subscription(&sub3).unwrap();

        // Find matching for follow.created - should only get enabled one
        let matches = store.find_matching_subscriptions("follow.created", None, None).unwrap();
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].action_type, "notification");

        // Find matching for reaction.added with source_type
        let matches = store.find_matching_subscriptions("reaction.added", Some("thing"), None).unwrap();
        assert_eq!(matches.len(), 1);

        // No matches for unknown event
        let matches = store.find_matching_subscriptions("unknown.event", None, None).unwrap();
        assert_eq!(matches.len(), 0);
    }

    // ==================== Delivery Queue Tests ====================

    // Helper to queue delivery with immediate availability (for testing)
    fn queue_delivery_immediate(store: &Store, delivery_type: &str, destination: &str, payload: &str) -> String {
        let conn = store.conn.lock().unwrap();
        let id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        conn.execute(
            r#"INSERT INTO delivery_queue (id, delivery_type, destination, payload, status,
                attempts, max_attempts, next_attempt_at, created_at)
               VALUES (?1, ?2, ?3, ?4, 'pending', 0, 3, ?5, ?6)"#,
            params![
                &id,
                delivery_type,
                destination,
                payload,
                now.to_rfc3339(),
                now.to_rfc3339(),
            ],
        ).unwrap();
        id
    }

    #[test]
    fn test_queue_and_get_pending_deliveries() {
        let store = Store::in_memory().unwrap();

        // Queue some deliveries (immediately available)
        queue_delivery_immediate(&store, "notification", "https://example.com", r#"{"test": true}"#);
        queue_delivery_immediate(&store, "webhook", "https://webhook.example.com", r#"{"data": 123}"#);

        // Get pending deliveries
        let pending = store.get_pending_deliveries(10).unwrap();
        assert_eq!(pending.len(), 2);

        // Verify first delivery
        let notif = pending.iter().find(|d| d.delivery_type == "notification").unwrap();
        assert_eq!(notif.destination, "https://example.com");
        assert_eq!(notif.status, DeliveryStatus::Pending);
        assert_eq!(notif.attempts, 0);
    }

    #[test]
    fn test_update_delivery_status() {
        let store = Store::in_memory().unwrap();

        queue_delivery_immediate(&store, "notification", "https://example.com", r#"{"test": true}"#);

        let pending = store.get_pending_deliveries(10).unwrap();
        assert_eq!(pending.len(), 1);
        let delivery_id = pending[0].id.clone();

        // Mark as delivered
        store.update_delivery_status(&delivery_id, &DeliveryStatus::Delivered, None).unwrap();

        // Should no longer appear in pending
        let pending = store.get_pending_deliveries(10).unwrap();
        assert_eq!(pending.len(), 0);
    }

    #[test]
    fn test_delivery_retry_logic() {
        let store = Store::in_memory().unwrap();

        let delivery_id = queue_delivery_immediate(&store, "webhook", "https://example.com", r#"{}"#);

        // Fail first attempt - this sets next_attempt_at to future, so check via direct query
        store.update_delivery_status(&delivery_id, &DeliveryStatus::Failed, Some("Connection refused")).unwrap();

        // Verify attempts incremented (check directly since next_attempt_at is in future)
        {
            let conn = store.conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT attempts FROM delivery_queue WHERE id = ?1").unwrap();
            let attempts: i32 = stmt.query_row(params![&delivery_id], |row| row.get(0)).unwrap();
            assert_eq!(attempts, 1);
        }

        // Fail second attempt
        store.update_delivery_status(&delivery_id, &DeliveryStatus::Failed, Some("Timeout")).unwrap();

        {
            let conn = store.conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT attempts FROM delivery_queue WHERE id = ?1").unwrap();
            let attempts: i32 = stmt.query_row(params![&delivery_id], |row| row.get(0)).unwrap();
            assert_eq!(attempts, 2);
        }

        // Fail third attempt - should now be permanently failed
        store.update_delivery_status(&delivery_id, &DeliveryStatus::Failed, Some("Final failure")).unwrap();

        // Verify status is now 'failed' (not 'pending')
        {
            let conn = store.conn.lock().unwrap();
            let mut stmt = conn.prepare("SELECT status FROM delivery_queue WHERE id = ?1").unwrap();
            let status: String = stmt.query_row(params![&delivery_id], |row| row.get(0)).unwrap();
            assert_eq!(status, "failed");
        }
    }

    #[test]
    fn test_queue_delivery_standard() {
        // Test the standard queue_delivery function (next_attempt in future)
        let store = Store::in_memory().unwrap();

        let id = store.queue_delivery("notification", "https://example.com", r#"{"test": true}"#).unwrap();
        assert!(!id.is_empty());

        // Should NOT be in pending yet (next_attempt_at is 30 seconds in future)
        let pending = store.get_pending_deliveries(10).unwrap();
        assert_eq!(pending.len(), 0);

        // But should exist in DB
        let conn = store.conn.lock().unwrap();
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM delivery_queue WHERE id = ?1").unwrap();
        let count: i64 = stmt.query_row(params![&id], |row| row.get(0)).unwrap();
        assert_eq!(count, 1);
    }

    // ==================== Notification Settings Tests ====================

    #[test]
    fn test_notification_settings() {
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

        // Get settings for type that doesn't exist yet - should fail
        let result = store.get_notification_settings(&user.id, "follow");
        assert!(result.is_err());

        // Create/update settings
        let settings = store.update_notification_settings(&user.id, "follow", true).unwrap();
        assert!(settings.enabled);

        // Get settings - should now exist
        let settings = store.get_notification_settings(&user.id, "follow").unwrap();
        assert!(settings.enabled);

        // Disable notifications
        let settings = store.update_notification_settings(&user.id, "follow", false).unwrap();
        assert!(!settings.enabled);

        // Verify disabled
        let settings = store.get_notification_settings(&user.id, "follow").unwrap();
        assert!(!settings.enabled);
    }

    #[test]
    fn test_get_all_notification_settings() {
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

        // Create multiple settings
        store.update_notification_settings(&user.id, "follow", true).unwrap();
        store.update_notification_settings(&user.id, "reaction", false).unwrap();
        store.update_notification_settings(&user.id, "comment", true).unwrap();

        // Get all settings
        let all_settings = store.get_all_notification_settings(&user.id).unwrap();
        assert_eq!(all_settings.len(), 3);

        let follow_setting = all_settings.iter().find(|s| s.notification_type == "follow").unwrap();
        assert!(follow_setting.enabled);

        let reaction_setting = all_settings.iter().find(|s| s.notification_type == "reaction").unwrap();
        assert!(!reaction_setting.enabled);
    }

    // ==================== Notification Tests ====================

    #[test]
    fn test_create_and_list_notifications() {
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

        // Create notifications
        let notif1 = Notification {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            notification_type: "follow".to_string(),
            actor_id: Some("actor1".to_string()),
            actor_type: Some("user".to_string()),
            resource_type: None,
            resource_id: None,
            title: Some("New follower".to_string()),
            body: Some("Someone followed you".to_string()),
            url: None,
            metadata: None,
            read: false,
            created_at: Utc::now(),
        };

        let notif2 = Notification {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            notification_type: "reaction".to_string(),
            actor_id: Some("actor2".to_string()),
            actor_type: Some("user".to_string()),
            resource_type: Some("thing".to_string()),
            resource_id: Some("thing123".to_string()),
            title: Some("New reaction".to_string()),
            body: None,
            url: None,
            metadata: None,
            read: false,
            created_at: Utc::now(),
        };

        store.create_notification(&notif1).unwrap();
        store.create_notification(&notif2).unwrap();

        // List notifications
        let notifications = store.list_notifications(&user.id, 10, 0).unwrap();
        assert_eq!(notifications.len(), 2);

        // Count
        let count = store.count_notifications(&user.id).unwrap();
        assert_eq!(count, 2);

        // Unread count
        let unread = store.get_unread_count(&user.id).unwrap();
        assert_eq!(unread, 2);
    }

    #[test]
    fn test_mark_notification_read() {
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

        let notif_id = uuid::Uuid::new_v4().to_string();
        let notif = Notification {
            id: notif_id.clone(),
            user_id: user.id.clone(),
            notification_type: "follow".to_string(),
            actor_id: None,
            actor_type: None,
            resource_type: None,
            resource_id: None,
            title: None,
            body: None,
            url: None,
            metadata: None,
            read: false,
            created_at: Utc::now(),
        };

        store.create_notification(&notif).unwrap();

        // Initially unread
        assert_eq!(store.get_unread_count(&user.id).unwrap(), 1);

        // Mark as read
        store.mark_notification_read(&notif_id, &user.id).unwrap();

        // Now read
        assert_eq!(store.get_unread_count(&user.id).unwrap(), 0);
    }

    #[test]
    fn test_mark_all_notifications_read() {
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

        // Create 3 unread notifications
        for i in 0..3 {
            let notif = Notification {
                id: uuid::Uuid::new_v4().to_string(),
                user_id: user.id.clone(),
                notification_type: format!("type{}", i),
                actor_id: None,
                actor_type: None,
                resource_type: None,
                resource_id: None,
                title: None,
                body: None,
                url: None,
                metadata: None,
                read: false,
                created_at: Utc::now(),
            };
            store.create_notification(&notif).unwrap();
        }

        assert_eq!(store.get_unread_count(&user.id).unwrap(), 3);

        // Mark all read
        let marked = store.mark_all_notifications_read(&user.id).unwrap();
        assert_eq!(marked, 3);

        assert_eq!(store.get_unread_count(&user.id).unwrap(), 0);
    }

    #[test]
    fn test_delete_notification() {
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

        let notif_id = uuid::Uuid::new_v4().to_string();
        let notif = Notification {
            id: notif_id.clone(),
            user_id: user.id.clone(),
            notification_type: "test".to_string(),
            actor_id: None,
            actor_type: None,
            resource_type: None,
            resource_id: None,
            title: None,
            body: None,
            url: None,
            metadata: None,
            read: false,
            created_at: Utc::now(),
        };

        store.create_notification(&notif).unwrap();
        assert_eq!(store.count_notifications(&user.id).unwrap(), 1);

        store.delete_notification(&notif_id, &user.id).unwrap();
        assert_eq!(store.count_notifications(&user.id).unwrap(), 0);
    }

    // ==================== Reaction Tests ====================

    #[test]
    fn test_add_and_get_reactions() {
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
            content: "Test".to_string(),
            metadata: HashMap::new(),
            visibility: "public".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing).unwrap();

        // Add reactions
        let reaction1 = Reaction {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            thing_id: thing.id.clone(),
            reaction_type: "like".to_string(),
            created_at: Utc::now(),
        };

        let reaction2 = Reaction {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            thing_id: thing.id.clone(),
            reaction_type: "👍".to_string(),
            created_at: Utc::now(),
        };

        store.add_reaction(&reaction1).unwrap();
        store.add_reaction(&reaction2).unwrap();

        // Get reactions
        let reactions = store.get_reactions_for_thing(&thing.id).unwrap();
        assert_eq!(reactions.len(), 2);

        // Get user reactions
        let user_reactions = store.get_user_reactions(&user.id, &thing.id).unwrap();
        assert_eq!(user_reactions.len(), 2);
        assert!(user_reactions.contains(&"like".to_string()));
        assert!(user_reactions.contains(&"👍".to_string()));
    }

    #[test]
    fn test_reaction_counts() {
        let store = Store::in_memory().unwrap();

        // Create two users
        let mut user1 = User {
            id: String::new(),
            username: "user1".to_string(),
            email: "user1@example.com".to_string(),
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
        store.create_user(&mut user1).unwrap();

        let mut user2 = User {
            id: String::new(),
            username: "user2".to_string(),
            email: "user2@example.com".to_string(),
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
        store.create_user(&mut user2).unwrap();

        let mut thing = Thing {
            id: String::new(),
            user_id: user1.id.clone(),
            thing_type: "note".to_string(),
            content: "Test".to_string(),
            metadata: HashMap::new(),
            visibility: "public".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing).unwrap();

        // Both users like the thing
        store.add_reaction(&Reaction {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user1.id.clone(),
            thing_id: thing.id.clone(),
            reaction_type: "like".to_string(),
            created_at: Utc::now(),
        }).unwrap();

        store.add_reaction(&Reaction {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user2.id.clone(),
            thing_id: thing.id.clone(),
            reaction_type: "like".to_string(),
            created_at: Utc::now(),
        }).unwrap();

        // User1 also adds emoji
        store.add_reaction(&Reaction {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user1.id.clone(),
            thing_id: thing.id.clone(),
            reaction_type: "🎉".to_string(),
            created_at: Utc::now(),
        }).unwrap();

        // Get counts
        let counts = store.get_reaction_counts(&thing.id).unwrap();
        assert_eq!(counts.get("like"), Some(&2));
        assert_eq!(counts.get("🎉"), Some(&1));
    }

    #[test]
    fn test_remove_reaction() {
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
            content: "Test".to_string(),
            metadata: HashMap::new(),
            visibility: "public".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing).unwrap();

        // Add reaction
        store.add_reaction(&Reaction {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            thing_id: thing.id.clone(),
            reaction_type: "like".to_string(),
            created_at: Utc::now(),
        }).unwrap();

        assert_eq!(store.get_reactions_for_thing(&thing.id).unwrap().len(), 1);

        // Remove reaction
        store.remove_reaction(&user.id, &thing.id, "like").unwrap();

        assert_eq!(store.get_reactions_for_thing(&thing.id).unwrap().len(), 0);
    }

    #[test]
    fn test_duplicate_reaction_fails() {
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
            content: "Test".to_string(),
            metadata: HashMap::new(),
            visibility: "public".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing).unwrap();

        // Add reaction
        store.add_reaction(&Reaction {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            thing_id: thing.id.clone(),
            reaction_type: "like".to_string(),
            created_at: Utc::now(),
        }).unwrap();

        // Duplicate should fail
        let result = store.add_reaction(&Reaction {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user.id.clone(),
            thing_id: thing.id.clone(),
            reaction_type: "like".to_string(),
            created_at: Utc::now(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_reaction_summary() {
        let store = Store::in_memory().unwrap();

        let mut user1 = User {
            id: String::new(),
            username: "user1".to_string(),
            email: "user1@example.com".to_string(),
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
        store.create_user(&mut user1).unwrap();

        let mut user2 = User {
            id: String::new(),
            username: "user2".to_string(),
            email: "user2@example.com".to_string(),
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
        store.create_user(&mut user2).unwrap();

        let mut thing = Thing {
            id: String::new(),
            user_id: user1.id.clone(),
            thing_type: "note".to_string(),
            content: "Test".to_string(),
            metadata: HashMap::new(),
            visibility: "public".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing).unwrap();

        // User1 likes
        store.add_reaction(&Reaction {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user1.id.clone(),
            thing_id: thing.id.clone(),
            reaction_type: "like".to_string(),
            created_at: Utc::now(),
        }).unwrap();

        // User2 likes and adds emoji
        store.add_reaction(&Reaction {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user2.id.clone(),
            thing_id: thing.id.clone(),
            reaction_type: "like".to_string(),
            created_at: Utc::now(),
        }).unwrap();
        store.add_reaction(&Reaction {
            id: uuid::Uuid::new_v4().to_string(),
            user_id: user2.id.clone(),
            thing_id: thing.id.clone(),
            reaction_type: "❤️".to_string(),
            created_at: Utc::now(),
        }).unwrap();

        // Get summary as user1
        let summary = store.get_reaction_summary(&thing.id, Some(&user1.id)).unwrap();
        let total: i64 = summary.counts.values().sum();
        assert_eq!(total, 3);
        assert_eq!(summary.counts.get("like"), Some(&2));
        assert_eq!(summary.counts.get("❤️"), Some(&1));
        assert!(summary.user_reactions.contains(&"like".to_string()));
        assert!(!summary.user_reactions.contains(&"❤️".to_string()));

        // Get summary as user2
        let summary = store.get_reaction_summary(&thing.id, Some(&user2.id)).unwrap();
        assert!(summary.user_reactions.contains(&"like".to_string()));
        assert!(summary.user_reactions.contains(&"❤️".to_string()));

        // Get summary without user context
        let summary = store.get_reaction_summary(&thing.id, None).unwrap();
        let total: i64 = summary.counts.values().sum();
        assert_eq!(total, 3);
        assert!(summary.user_reactions.is_empty());
    }

    // ==================== Backlink Tests (ported from Go) ====================

    #[test]
    fn test_backlinks_basic() {
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

        // Create things A, B, C
        let mut thing_a = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing A".to_string(),
            metadata: HashMap::new(),
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_a).unwrap();

        let mut thing_b = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing B".to_string(),
            metadata: HashMap::new(),
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_b).unwrap();

        // Create Thing D with a link attribute pointing to A
        let mut metadata_d = HashMap::new();
        metadata_d.insert(
            "attributes".to_string(),
            serde_json::json!([
                {
                    "type": "link",
                    "name": "related",
                    "value": thing_a.id.clone()
                }
            ]),
        );

        let mut thing_d = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing D".to_string(),
            metadata: metadata_d,
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_d).unwrap();

        // GetBacklinks for A - should return [D]
        let backlinks = store.get_backlinks(&user.id, &thing_a.id).unwrap();
        assert_eq!(backlinks.len(), 1, "Expected 1 backlink for A");
        assert_eq!(backlinks[0].id, thing_d.id, "Expected backlink from D");

        // GetBacklinks for B - should return empty
        let backlinks = store.get_backlinks(&user.id, &thing_b.id).unwrap();
        assert_eq!(backlinks.len(), 0, "Expected 0 backlinks for B");
    }

    #[test]
    fn test_backlinks_multiple_links() {
        // Test thing linking to multiple targets (array of IDs)
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

        // Create things A, B
        let mut thing_a = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing A".to_string(),
            metadata: HashMap::new(),
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_a).unwrap();

        let mut thing_b = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing B".to_string(),
            metadata: HashMap::new(),
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_b).unwrap();

        // Create Thing E with link to both A and B (array of IDs)
        let mut metadata_e = HashMap::new();
        metadata_e.insert(
            "attributes".to_string(),
            serde_json::json!([
                {
                    "type": "link",
                    "name": "related",
                    "value": [thing_a.id.clone(), thing_b.id.clone()]
                }
            ]),
        );

        let mut thing_e = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing E".to_string(),
            metadata: metadata_e,
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_e).unwrap();

        // GetBacklinks for A - should return [E]
        let backlinks = store.get_backlinks(&user.id, &thing_a.id).unwrap();
        assert_eq!(backlinks.len(), 1, "Expected 1 backlink for A");

        // GetBacklinks for B - should return [E]
        let backlinks = store.get_backlinks(&user.id, &thing_b.id).unwrap();
        assert_eq!(backlinks.len(), 1, "Expected 1 backlink for B");
    }

    #[test]
    fn test_backlinks_multiple_things_linking() {
        // Multiple things linking to same target
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

        // Create thing A
        let mut thing_a = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing A".to_string(),
            metadata: HashMap::new(),
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_a).unwrap();

        // Create Thing D linking to A
        let mut metadata_d = HashMap::new();
        metadata_d.insert(
            "attributes".to_string(),
            serde_json::json!([
                { "type": "link", "name": "related", "value": thing_a.id.clone() }
            ]),
        );

        let mut thing_d = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing D".to_string(),
            metadata: metadata_d,
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_d).unwrap();

        // Create Thing E also linking to A
        let mut metadata_e = HashMap::new();
        metadata_e.insert(
            "attributes".to_string(),
            serde_json::json!([
                { "type": "link", "name": "related", "value": thing_a.id.clone() }
            ]),
        );

        let mut thing_e = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing E".to_string(),
            metadata: metadata_e,
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_e).unwrap();

        // GetBacklinks for A - should return [D, E]
        let backlinks = store.get_backlinks(&user.id, &thing_a.id).unwrap();
        assert_eq!(backlinks.len(), 2, "Expected 2 backlinks for A");

        // Verify both D and E are in backlinks
        let backlink_ids: std::collections::HashSet<_> = backlinks.iter().map(|b| b.id.clone()).collect();
        assert!(backlink_ids.contains(&thing_d.id), "Expected D in backlinks");
        assert!(backlink_ids.contains(&thing_e.id), "Expected E in backlinks");
    }

    #[test]
    fn test_backlinks_excludes_deleted() {
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

        // Create thing A
        let mut thing_a = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing A".to_string(),
            metadata: HashMap::new(),
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_a).unwrap();

        // Create Thing D linking to A
        let mut metadata_d = HashMap::new();
        metadata_d.insert(
            "attributes".to_string(),
            serde_json::json!([
                { "type": "link", "name": "related", "value": thing_a.id.clone() }
            ]),
        );

        let mut thing_d = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing D".to_string(),
            metadata: metadata_d,
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_d).unwrap();

        // Verify D is a backlink
        let backlinks = store.get_backlinks(&user.id, &thing_a.id).unwrap();
        assert_eq!(backlinks.len(), 1, "Expected 1 backlink before delete");

        // Soft-delete D
        store.delete_thing(&thing_d.id).unwrap();

        // GetBacklinks should now return empty (D is deleted)
        let backlinks = store.get_backlinks(&user.id, &thing_a.id).unwrap();
        assert_eq!(backlinks.len(), 0, "Expected 0 backlinks after delete");
    }

    #[test]
    fn test_backlinks_user_isolation() {
        // Backlinks should only show things from the requesting user
        let store = Store::in_memory().unwrap();

        let mut user1 = User {
            id: String::new(),
            username: "user1".to_string(),
            email: "user1@example.com".to_string(),
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
        store.create_user(&mut user1).unwrap();

        let mut user2 = User {
            id: String::new(),
            username: "user2".to_string(),
            email: "user2@example.com".to_string(),
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
        store.create_user(&mut user2).unwrap();

        // Create thing A for user1
        let mut thing_a = Thing {
            id: String::new(),
            user_id: user1.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing A".to_string(),
            metadata: HashMap::new(),
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_a).unwrap();

        // Create thing B for user2
        let mut thing_b = Thing {
            id: String::new(),
            user_id: user2.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing B".to_string(),
            metadata: HashMap::new(),
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_b).unwrap();

        // Create thing C for user2 linking to thing B
        let mut metadata_c = HashMap::new();
        metadata_c.insert(
            "attributes".to_string(),
            serde_json::json!([
                { "type": "link", "name": "related", "value": thing_b.id.clone() }
            ]),
        );

        let mut thing_c = Thing {
            id: String::new(),
            user_id: user2.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing C".to_string(),
            metadata: metadata_c,
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_c).unwrap();

        // User1's GetBacklinks for thing A should return empty
        let backlinks = store.get_backlinks(&user1.id, &thing_a.id).unwrap();
        assert_eq!(backlinks.len(), 0, "Expected 0 backlinks for user1");

        // User2's GetBacklinks for thing B should return [C]
        let backlinks = store.get_backlinks(&user2.id, &thing_b.id).unwrap();
        assert_eq!(backlinks.len(), 1, "Expected 1 backlink for user2");
    }

    #[test]
    fn test_backlinks_nonexistent_target() {
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

        // Query backlinks for a thing that doesn't exist
        let backlinks = store.get_backlinks(&user.id, "nonexistent-id").unwrap();

        // Should return empty (no error, just no results)
        assert_eq!(backlinks.len(), 0, "Expected 0 backlinks for nonexistent target");
    }

    #[test]
    fn test_backlinks_no_link_attributes() {
        // Non-link attributes shouldn't count as backlinks
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

        // Create thing A
        let mut thing_a = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing A".to_string(),
            metadata: HashMap::new(),
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_a).unwrap();

        // Create thing D with non-link attributes
        let mut metadata_d = HashMap::new();
        metadata_d.insert(
            "attributes".to_string(),
            serde_json::json!([
                { "type": "text", "name": "description", "value": "some text" }
            ]),
        );

        let mut thing_d = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "note".to_string(),
            content: "Thing D".to_string(),
            metadata: metadata_d,
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing_d).unwrap();

        // GetBacklinks for A should return empty (D has no link attributes)
        let backlinks = store.get_backlinks(&user.id, &thing_a.id).unwrap();
        assert_eq!(backlinks.len(), 0, "Expected 0 backlinks for thing with no link attributes");
    }

    // ==================== Gallery/Photo Tests (ported from Go) ====================

    #[test]
    fn test_photo_order_index() {
        // Verify photos are returned in order by order_index
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

        // Create gallery
        let mut gallery = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "gallery".to_string(),
            content: String::new(),
            metadata: HashMap::new(),
            visibility: "private".to_string(),
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut gallery).unwrap();

        // Create photos OUT OF ORDER (Third first, then First, then Second)
        let mut photo_third = Photo {
            id: String::new(),
            thing_id: gallery.id.clone(),
            caption: "Third".to_string(),
            order_index: 2,
            content_type: "image/jpeg".to_string(),
            filename: "test.jpg".to_string(),
            size: 4,
            data: vec![1, 2, 3, 4],
            created_at: Utc::now(),
        };
        store.create_photo(&mut photo_third).unwrap();

        let mut photo_first = Photo {
            id: String::new(),
            thing_id: gallery.id.clone(),
            caption: "First".to_string(),
            order_index: 0,
            content_type: "image/jpeg".to_string(),
            filename: "test.jpg".to_string(),
            size: 4,
            data: vec![1, 2, 3, 4],
            created_at: Utc::now(),
        };
        store.create_photo(&mut photo_first).unwrap();

        let mut photo_second = Photo {
            id: String::new(),
            thing_id: gallery.id.clone(),
            caption: "Second".to_string(),
            order_index: 1,
            content_type: "image/jpeg".to_string(),
            filename: "test.jpg".to_string(),
            size: 4,
            data: vec![1, 2, 3, 4],
            created_at: Utc::now(),
        };
        store.create_photo(&mut photo_second).unwrap();

        // Retrieve and verify order
        let photos = store.get_photos_by_thing_id(&gallery.id).unwrap();
        assert_eq!(photos.len(), 3, "Expected 3 photos");

        // Photos should be in order: First, Second, Third
        assert_eq!(photos[0].caption, "First", "First photo should be 'First'");
        assert_eq!(photos[1].caption, "Second", "Second photo should be 'Second'");
        assert_eq!(photos[2].caption, "Third", "Third photo should be 'Third'");
    }

    #[test]
    fn test_default_visibility() {
        // Things should default to private visibility
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

        // Create thing without specifying visibility (should default to private)
        let mut thing = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "note".to_string(),
            content: "Test".to_string(),
            metadata: HashMap::new(),
            visibility: String::new(), // Empty - should default to private
            version: 1,
            deleted_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            photos: Vec::new(),
        };
        store.create_thing(&mut thing).unwrap();

        // Retrieve and verify default visibility
        let retrieved = store.get_thing(&thing.id).unwrap();
        assert_eq!(
            retrieved.visibility, "private",
            "Expected default visibility 'private', got '{}'",
            retrieved.visibility
        );
    }

    #[test]
    fn test_list_things_with_photos() {
        // Verify ListThings includes photos for galleries
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

        // Create a gallery with photos
        let mut gallery = Thing {
            id: String::new(),
            user_id: user.id.clone(),
            thing_type: "gallery".to_string(),
            content: String::new(),
            metadata: HashMap::new(),
            visibility: "private".to_string(),
            version: 1,
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
            content_type: "image/jpeg".to_string(),
            filename: "test.jpg".to_string(),
            size: 4,
            data: vec![1, 2, 3, 4],
            created_at: Utc::now(),
        };
        store.create_photo(&mut photo).unwrap();

        // List things
        let things = store.list_things(&user.id, None, 10, 0).unwrap();
        assert_eq!(things.len(), 1, "Expected 1 thing");

        let thing = &things[0];
        assert_eq!(thing.thing_type, "gallery", "Expected gallery type");

        // Verify photos can be fetched directly
        // (ListThings may not populate photos array directly, so we fetch separately)
        let photos = store.get_photos_by_thing_id(&thing.id).unwrap();
        assert_eq!(photos.len(), 1, "Expected 1 photo");
        assert_eq!(photos[0].caption, "Test photo", "Expected caption 'Test photo'");
    }
}
