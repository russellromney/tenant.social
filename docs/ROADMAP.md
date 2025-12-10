# Tenant Roadmap

## Completed

### Core Features
- [x] Multi-user authentication (register, login, sessions)
- [x] User-scoped data (Things, Kinds, Tags, Views)
- [x] Server admin role (first user is admin)
- [x] Admin can lock/unlock users
- [x] Admin can delete users
- [x] API Key System (CRUD, scopes, auth middleware, UI)
- [x] Query API Enhancements (filtering, sorting, pagination, metadata queries)
- [x] Bulk Operations (create, update, delete up to 100 items)
- [x] Thing Version History (automatic versioning, view history, revert to version)
- [x] Photo/Gallery support with captions
- [x] Rate limiting (10 req/sec per IP)

### Social Foundation
- [x] Follows system (follow/unfollow, followers list, following list, mutuals)
- [x] Friend feed (Things from followed users with `friends`/`public` visibility)
- [x] Visibility levels on Things (`private`, `friends`, `public`)
- [x] Public profile endpoint (`/api/public/profile`)
- [x] Public things endpoint (`/api/public/things`)
- [x] Federation endpoint (`/api/fed/things/{user_id}`)

### Infrastructure
- [x] Rust backend migration (actix-web, rusqlite)
- [x] Metrics and monitoring endpoints
- [x] Thing backlinks (`GET /api/things/{id}/backlinks`)

---

## In Progress

### Social Features (see SOCIAL_IMPLEMENTATION_PLAN.md)

**Phase 1: Notifications**
- [ ] Notifications table and model
- [ ] List/mark-read/delete endpoints
- [ ] Unread count endpoint
- [ ] Create notification on follow

**Phase 2: Reactions**
- [ ] Reactions table (1 like + 1 emoji per user per Thing)
- [ ] Add/remove reaction endpoints
- [ ] Reaction counts in Thing response
- [ ] Notification on reaction

**Phase 3: Comments**
- [ ] Comments as Things with `type=comment`
- [ ] Max thread depth of 3
- [ ] One top-level comment per user per Thing
- [ ] Comment count in Thing response
- [ ] Notification on comment

**Phase 4: Mentions**
- [ ] Parse `@username` in content
- [ ] Create notification for mentioned users

---

## Next Up

### Thing Linking (Unidirectional)
Things can link to other Things via a "link" attribute type:
1. **Link attribute**: New attribute type `link` stores a Thing ID
2. **Backlinks endpoint**: `GET /api/things/{id}/backlinks` - find what links to this Thing ✅
3. **Link UI**: Search/select dropdown to link to other Things
4. **Display**: Show linked Things in Thing view with preview

### Channels API
Database table exists, needs API exposure:
- Create/list/delete channels
- Add/remove members
- Channel roles (owner, admin, member)

---

## Future

### Recovery & Backup
- [ ] Recovery phrase system (BIP39 mnemonic for account recovery)
- [ ] Encrypted data backup/restore
- [ ] Data export (JSON dump of all user data)

### Search & Discovery
- [ ] Full-text search with FTS5
- [ ] User search/discovery

### Developer Features
- [ ] Webhooks (notify external systems on data changes)
- [ ] Audit log (track API key usage)
- [ ] Configurable per-key rate limits

### Security
- [ ] Block/mute users
- [ ] Data encryption at rest (optional, per-user)

---

## API Reference

### Existing Endpoints

**Auth**
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `GET /api/auth/status` - Check if instance has owner
- `GET /api/auth/me` - Get current user

**Things**
- `GET /api/things` - List things
- `POST /api/things` - Create thing
- `GET /api/things/{id}` - Get thing
- `PUT /api/things/{id}` - Update thing
- `DELETE /api/things/{id}` - Delete thing
- `GET /api/things/{id}/backlinks` - Get backlinks

**Photos**
- `POST /api/upload` - Upload photos (creates gallery Thing)
- `GET /api/photos/{id}` - Serve photo

**API Keys**
- `GET /api/keys` - List keys
- `POST /api/keys` - Create key
- `DELETE /api/keys/{id}` - Delete key

**Kinds**
- `GET /api/kinds` - List kinds
- `POST /api/kinds` - Create kind
- `GET /api/kinds/{id}` - Get kind
- `PUT /api/kinds/{id}` - Update kind
- `DELETE /api/kinds/{id}` - Delete kind

**Social**
- `POST /api/friends` - Add friend (follow)
- `DELETE /api/follows/{user_id}` - Unfollow
- `GET /api/follows/followers` - List followers
- `GET /api/follows/following` - List following
- `GET /api/follows/mutuals` - List mutual followers
- `GET /api/feed/friends` - Friend feed

**Public**
- `GET /api/public/profile` - Get owner profile
- `GET /api/public/things` - Get public things

**Federation**
- `GET /api/fed/things/{user_id}` - Get friend-visible things (for remote nodes)

### Planned Endpoints (Social)

**Notifications**
- `GET /api/notifications` - List notifications
- `GET /api/notifications/unread-count` - Unread count
- `PUT /api/notifications/read-all` - Mark all read
- `PUT /api/notifications/{id}/read` - Mark single read
- `DELETE /api/notifications/{id}` - Delete notification

**Reactions**
- `POST /api/things/{id}/reactions` - Add reaction
- `DELETE /api/things/{id}/reactions/{type}` - Remove reaction
- `GET /api/things/{id}/reactions` - Get reactions

**Comments**
- `GET /api/things/{id}/comments` - List comments
- `POST /api/things/{id}/comments` - Create comment
