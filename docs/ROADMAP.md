# Tenant Roadmap

## Completed
- [x] Multi-user authentication (register, login, sessions)
- [x] User-scoped data (Things, Kinds, Tags, Views)
- [x] Server admin role (first user is admin)
- [x] Admin can lock/unlock users
- [x] Admin can delete users
- [x] API Key System (CRUD, scopes, auth middleware, UI)
- [x] Query API Enhancements (filtering, sorting, pagination, metadata queries)
- [x] Bulk Operations (create, update, delete up to 100 items)
- [x] Thing Version History (automatic versioning, view history, revert to version)

## In Progress

### Thing Linking (Unidirectional)
Things can link to other Things as attributes. A Thing stores IDs of Things it links to. When viewing a Thing, see what links to it via backlinks query.

**Current scope:**
- Add "link" attribute type (stores Thing ID in metadata)
- Backlinks endpoint: `GET /api/things/{id}/backlinks`
- UI: dropdown/search to select Things to link to
- Display linked Things in view

**Unidirectional design:** Only the linking Thing stores the reference. To find backlinks, query all Things and check their attributes.

### API Key System (Reference)
Programmatic access for integrations (personal website, scripts, apps):

**API Key Model:**
```go
type APIKey struct {
    ID         string
    UserID     string
    Name       string      // "Personal Website", "Chrome Extension"
    KeyHash    string      // bcrypt hash (never store raw key)
    KeyPrefix  string      // "ts_abc123" (first 8 chars for UI identification)
    Scopes     []string    // granular permissions
    Metadata   JSON        // arbitrary user metadata (environment, repo, etc.)
    LastUsedAt *time.Time
    ExpiresAt  *time.Time  // optional, default never
    CreatedAt  time.Time
}
```

**Granular Scopes:**
- `things:read` - list/get things
- `things:write` - create/update things
- `things:delete` - delete things (separate from write!)
- `kinds:read`, `kinds:write`, `kinds:delete`
- `tags:read`, `tags:write`, `tags:delete`
- `keys:manage` - create/revoke API keys

**Key Format:** `ts_<random_32_chars>` - shown once at creation, stored as bcrypt hash

**Endpoints:**
- `POST /api/keys` - create key (returns raw key ONCE)
- `GET /api/keys` - list your keys (metadata only)
- `PUT /api/keys/:id` - update name/scopes/metadata
- `DELETE /api/keys/:id` - revoke key

**Auth:** `Authorization: Bearer ts_xxxxx`

### Query API Enhancements
Advanced filtering and pagination for Things:

```
GET /api/things?type=article&meta.status=queued&sort=-createdAt&page=1&count=20
GET /api/things?type=article&count=all
```

**Features:**
- Filter by type
- Filter by metadata fields (`meta.fieldname=value`)
- Sort by any field (`sort=createdAt`, `sort=-createdAt` for desc)
- Pagination: `page=N&count=M` or `count=all`
- Upsert: `PUT /api/things/upsert?type=article&meta.url=https://...`

### Bulk Operations
Efficient batch operations:

```
POST /api/things/bulk   - create many
PUT /api/things/bulk    - update many
DELETE /api/things/bulk - delete many (by IDs)
```

### Rate Limiting
- 10 operations per second per IP
- Configurable per-key limits (future)

### Thing Version History
Every Thing edit creates a new version - never lose data:

```go
type ThingVersion struct {
    ID        string
    ThingID   string
    Version   int
    Content   string
    Metadata  JSON
    CreatedAt time.Time
    CreatedBy string    // user ID or API key ID
}
```

**Endpoints:**
- `GET /api/things/:id` - returns latest version
- `GET /api/things/:id/versions` - returns version history
- `GET /api/things/:id/versions/:version` - returns specific version
- Deletes are soft-deletes (can be restored)

## Next Up

### Thing Linking (Unidirectional)
Things can link to other Things via a "link" attribute type:
1. **Link attribute**: New attribute type `link` stores a Thing ID
2. **Backlinks endpoint**: `GET /api/things/{id}/backlinks` - find what links to this Thing
3. **Link UI**: Search/select dropdown to link to other Things
4. **Display**: Show linked Things in Thing view with preview
5. **Future**: Add bidirectional support (maintains consistency on both sides, higher complexity)

### Recovery Phrase System
Users need a recovery phrase for account recovery and data export:
1. **On registration**: Generate a 12-24 word mnemonic phrase (BIP39 style)
2. **Store hash**: Store bcrypt hash of the phrase in `recovery_hash` field
3. **User must save**: Show phrase ONCE, require user to confirm they saved it
4. **Password recovery**: If user forgets password but has recovery phrase:
   - Verify recovery phrase
   - Allow password reset
5. **Locked account data export**: If admin locks a user:
   - User can still use recovery phrase to export their data
   - Data export is read-only, no modifications allowed
6. **Admin recovery**: Admin also gets a recovery phrase for password recovery

### Encrypted Data Backup
For when servers shut down or users want portable backups:
1. **Encryption key derivation**: Derive encryption key from recovery phrase
2. **Export encrypted backup**:
   - Export all user data (Things, Kinds, Tags, Views, Photos)
   - Encrypt with key derived from recovery phrase
   - Produce single downloadable file
3. **Import to new server**:
   - User creates account on new server
   - Uploads encrypted backup
   - Enters recovery phrase to decrypt
   - Data is imported to new account

### Future Features
- [ ] Public profiles (optional, user-controlled)
- [ ] Sharing Things between users
- [ ] Full-text search with FTS5
- [ ] Data encryption at rest (optional, per-user)

### Webhooks (Future)
Real-time notifications when data changes:

```go
type Webhook struct {
    ID        string
    UserID    string
    URL       string
    Events    []string  // "thing.created", "thing.updated", "thing.deleted"
    Secret    string    // for HMAC signature verification
    Active    bool
    CreatedAt time.Time
}
```

When a Thing changes → POST to webhook URL with signed payload.

### Audit Log (Future)
Track API key usage for debugging integrations:

```go
type APIKeyUsage struct {
    ID        string
    KeyID     string
    UserID    string
    Endpoint  string
    Method    string
    Status    int
    Timestamp time.Time
}
```

- Store last N requests per key
- Queryable for debugging
- Auto-cleanup after 30 days
