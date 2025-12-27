# Comment/Reply System Implementation Plan

## Core Requirements

### Comment Rules
- **Unlimited** comments per user per Thing (not one-per-user)
- **Max depth**: 3 (4 total levels: post → comment → reply → reply → reply)
- **Federated**: Same visibility rules as Things
- **Operations**: Create/reply, Edit (with history), Delete (tombstone), React

### Data Residency & Ownership
- **Comment metadata** lives on post owner's instance (discussion owned by poster)
- **Media files** (gifs/images) live on commenter's instance (prevent storage spam)
- Comments reference media via URL: `https://commenter-instance.com/media/abc123.gif`

### Deletion & Privacy ("Disappear")
**Comment deletion (two paths):**
1. **Commenter deletes own comment** - user can remove their own words
2. **Post owner deletes comment on their post** - owner can moderate their discussion

Both result in:
- Content replaced with `[deleted]` tombstone
- Thread structure preserved (replies remain visible)
- Instances that cached original can optionally show it ("View deleted comment")
- New viewers only see tombstone
- Media URLs break when commenter deletes/disappears

**Account deletion:**
- All user's Things → tombstoned
- All user's comments → tombstoned
- Profile deleted/inaccessible
- Cached copies remain on other instances (federation reality)
- After cache expiry, user effectively disappeared

### Architecture (from whitepaper)
- Comments are Things with `type="comment"`
- Metadata: `{ "parent_id": "...", "root_id": "...", "depth": 0-3 }`
- Existing Thing version system for edit history
- Existing soft delete (`deleted_at`) for tombstoning
- Reactions already work on all Things (including comments)

## Current State

✅ **Already Implemented:**
- Thing model with metadata (HashMap<String, Value>)
- Event/notification system (Phase 1)
- Reactions (Phase 2)
- Version history system
- Soft delete system with `deleted_at`

❌ **Not Implemented:**
- Comment-specific API endpoints
- Comment metadata validation (parent_id, root_id, depth)
- Depth limit enforcement (max depth=3)
- Comment queries (list comments for Thing, list replies for comment)
- Event emission on comment creation
- Media reference handling in comments
- Tombstone rendering for deleted comments

## Implementation Plan

### 1. Store Layer (store/mod.rs)
Add comment query methods:
- `get_comments_for_thing(thing_id: &str) -> Vec<Thing>` - Get all comments for a Thing
- `get_replies(comment_id: &str) -> Vec<Thing>` - Get direct replies to a comment
- `get_comment_thread(root_id: &str) -> Vec<Thing>` - Get entire comment tree
- `get_root_thing_owner(thing_id: &str) -> Option<String>` - Get owner of root Thing (for auth check)
- Validate depth limit in create/update operations

### 2. API Layer (api/mod.rs)

**Local comment creation:**
- `POST /api/things/:id/comments` - Create comment on own instance (auth required)
  - Validate: depth ≤3, parent exists, metadata structure
  - Emit `comment.created` event
  - Return created comment

**Federated comment creation (token-based like follows):**
- `POST /api/comments/create-token` - Create comment verification token (auth required)
  - Returns ephemeral token (5-min expiry)
  - Stored in-memory like follow tokens

- `POST /api/fed/comments` - Receive federated comment (public endpoint)
  - Payload: `{ commenter_user_id, commenter_endpoint, thing_id, content, metadata, comment_token }`
  - Verifies token via `POST {commenter_endpoint}/api/fed/verify-comment-token`
  - Creates comment if valid
  - Emits event → notification to post owner

- `POST /api/fed/verify-comment-token` - Verify comment token (public endpoint)
  - Returns `{ valid: bool, user_id, endpoint }` like follow verification

**Comment retrieval:**
- `GET /api/things/:id/comments` - List comments for Thing
  - Returns flat list with depth/parent_id (frontend builds tree)
  - Includes tombstoned comments with `deleted_at`

- `GET /api/fed/things/:thing_id/comments` - Federated comment access (public endpoint)
  - Returns comments filtered by root Thing visibility
  - Only returns if root Thing is public/friends

**Comment deletion:**
- `DELETE /api/things/:id` - Delete Thing/comment (auth required)
  - Allow if: requester is comment author OR requester owns root Thing
  - Sets `deleted_at` timestamp (tombstone)
  - Emits `comment.deleted` event

### 3. Federation Flow

**User on Instance B comments on post from Instance A:**
1. User writes comment in frontend
2. Frontend calls `POST {instanceA}/api/comments/create-token` to get token from Instance A
3. Frontend calls `POST {instanceA}/api/fed/comments` with token
4. Instance A verifies token via callback to Instance B
5. Instance A stores comment, emits event, sends notification

**Performance notes:**
- Rust VMs handle high concurrent load well
- SQLite reads are fast - don't optimize for minimal queries
- API can be "chatty" if it leads to clearer behavior
- Prioritize correctness over call count

### 4. Store Implementation Details

**Token storage (like follows):**
```rust
pub comment_tokens: Arc<Mutex<HashMap<String, CommentToken>>>
```

**Comment metadata validation:**
```rust
fn validate_comment_metadata(metadata: &HashMap<String, Value>) -> Result<(), String> {
    // Must have parent_id (or null for top-level)
    // Must have root_id
    // Must have depth: 0-3
}
```

**Root Thing owner lookup for auth:**
```rust
// Walk up tree to find root Thing owner
// Check if requester == owner for deletion rights
```

### 5. Media Handling
- Comments can include media URLs in content or metadata
- Media lives on commenter's instance (prevent storage spam)
- No special handling - just URLs that break on commenter deletion

### 6. Tombstone Rendering
API returns deleted comments with:
```json
{
  "id": "...",
  "content": "[deleted]",
  "deleted_at": "2025-01-15T...",
  "metadata": { "parent_id": "...", "root_id": "...", "depth": 1 }
}
```
Frontend shows tombstone + optional cached version if available.

### 7. Testing Plan
Comprehensive tests for:
- **Local comments:** Create, depth limits, thread structure
- **Federated comments:** Token creation/verification, cross-instance comments
- **Deletion:** Both paths (owner deletes comment, commenter deletes own)
- **Tombstoning:** Deleted content shows as `[deleted]`, thread preserved
- **Events:** Verify emission on create/delete
- **Edge cases:** Invalid depth, missing parent, expired tokens
- **Concurrency:** Multiple comments at once (SQLite handles it)
- **Media:** URLs in comments, broken URLs after deletion

## Critical Files

- `/backend-rust/tenant-vm/src/models/mod.rs` - Thing model (no changes needed)
- `/backend-rust/tenant-vm/src/store/mod.rs` - Add comment query methods
- `/backend-rust/tenant-vm/src/api/mod.rs` - Add comment endpoints
- `/backend-rust/tenant-vm/src/events/mod.rs` - Event emission (helper exists)
- `/backend-rust/tenant-vm/tests/` - Add comment tests
