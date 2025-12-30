# Tenant.Social Implementation Plan

## Overview

This document outlines the roadmap for implementing three major feature sets:
1. Gallery photos with multi-photo posts and captions
2. Public profiles with selective visibility
3. Friendships/follow system with friend feed

## Key Design Decisions

- **Gallery Model**: Every photo is part of a gallery Thing. A single photo is just a gallery with one photo.
- **Visibility Levels**: Three tiers - private (owner only), friends (owner + connections), public (everyone)
- **Public Profiles**: Profiles are public, but individual profile elements can be hidden (bio, avatar, stats)
- **Friend Feed**: Uses cached post IDs with fresh content fetching (ensures access control is current)
- **Friendship Model**: One-directional follows, with accept/reject/remove functionality

## Phase 1: Gallery Photos with Multi-Photo Support

### Objective
Enable users to upload multiple photos in a single post with individual captions.

### Database Changes

```sql
-- Add caption and order_index to photos
ALTER TABLE photos ADD COLUMN caption TEXT;
ALTER TABLE photos ADD COLUMN order_index INTEGER DEFAULT 0;
CREATE INDEX idx_photos_thing_order ON photos(thing_id, order_index);
```

### Model Changes

**Photo Model** (`internal/models/models.go`):
```go
type Photo struct {
    ID          string    `json:"id"`
    ThingID     string    `json:"thingId"`      // Associated gallery Thing
    Caption     string    `json:"caption"`      // Per-photo caption
    OrderIndex  int       `json:"orderIndex"`   // Position in carousel (0, 1, 2...)
    Data        []byte    `json:"-"`            // Binary data (not serialized)
    ContentType string    `json:"contentType"`  // MIME type
    Filename    string    `json:"filename"`     // Original filename
    Size        int64     `json:"size"`         // File size in bytes
    CreatedAt   time.Time `json:"createdAt"`
}
```

**Thing Model Update** (`internal/models/models.go`):
```go
type Thing struct {
    ID        string                 `json:"id"`
    UserID    string                 `json:"userId"`
    Type      string                 `json:"type"`      // "note", "link", "gallery", etc.
    Content   string                 `json:"content"`   // Post text/caption
    Metadata  map[string]interface{} `json:"metadata"`
    Version   int                    `json:"version"`
    DeletedAt *time.Time             `json:"deletedAt"`
    CreatedAt time.Time              `json:"createdAt"`
    UpdatedAt time.Time              `json:"updatedAt"`

    // Populated when fetching (not stored in DB)
    Photos    []Photo                `json:"photos,omitempty"`
}
```

### API Endpoints

**Photo Upload** (`POST /api/upload`):
- Accept: `files[]` (multiple files), `captions[]` (per-photo captions), `content` (post text)
- Returns: Single Thing of type "gallery" with all photos in order
- Creates: One Thing + multiple Photo records

**Request Format**:
```json
{
  "files": [file1, file2, file3],
  "captions": ["First photo", "Second photo", "Third photo"],
  "content": "Optional post text"
}
```

**Response**:
```json
{
  "id": "thing123",
  "userId": "user456",
  "type": "gallery",
  "content": "Optional post text",
  "visibility": "private",
  "photos": [
    {
      "id": "photo1",
      "caption": "First photo",
      "orderIndex": 0,
      "contentType": "image/jpeg",
      "url": "/api/photos/photo1"
    },
    {
      "id": "photo2",
      "caption": "Second photo",
      "orderIndex": 1,
      "contentType": "image/jpeg",
      "url": "/api/photos/photo2"
    }
  ]
}
```

### Store/Database Layer Changes

**Update `store.go`**:
- Modify `CreateThing()` to accept array of photos
- Modify `GetThing()` to fetch associated photos ordered by `order_index`
- Add `GetPhotosByThingID(thingID)` to fetch all photos for a Thing

### Frontend Changes

**Photo Upload Component**:
- Accept multiple file inputs with individual caption fields
- Preview gallery before posting
- Show remove button for each photo

**Photo Carousel Display**:
- Display first photo by default
- Add left/right arrow buttons to navigate
- Show caption below current photo
- Show photo counter (e.g., "1 of 3")
- Handle keyboard navigation (← →)

---

## Phase 2: Visibility Levels & Public Profiles

### Objective
Enable users to control visibility of their content and create public profiles with selective public fields.

### Database Changes

```sql
-- Add visibility to things
ALTER TABLE things ADD COLUMN visibility TEXT CHECK(visibility IN ('private', 'friends', 'public')) DEFAULT 'private';
CREATE INDEX idx_things_visibility ON things(visibility);

-- Add public settings to users
ALTER TABLE users ADD COLUMN is_public_bio BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN is_public_avatar BOOLEAN DEFAULT false;
ALTER TABLE users ADD COLUMN is_public_stats BOOLEAN DEFAULT false;
```

### Model Changes

**Thing Model Update**:
```go
type Thing struct {
    // ... existing fields ...
    Visibility string `json:"visibility"` // "private", "friends", "public"
}
```

**User Model Update** (`internal/models/models.go`):
```go
type User struct {
    ID              string    `json:"id"`
    Username        string    `json:"username"`
    Email           string    `json:"-"`              // Never exposed
    PasswordHash    string    `json:"-"`              // Never exposed
    DisplayName     string    `json:"displayName"`
    Bio             string    `json:"bio"`
    AvatarURL       string    `json:"avatarUrl"`
    IsAdmin         bool      `json:"isAdmin"`
    IsLocked        bool      `json:"isLocked"`
    RecoveryHash    string    `json:"-"`              // Never exposed
    IsPublicBio     bool      `json:"isPublicBio"`    // Make bio visible to others
    IsPublicAvatar  bool      `json:"isPublicAvatar"` // Make avatar visible to others
    IsPublicStats   bool      `json:"isPublicStats"`  // Show follower/following counts
    CreatedAt       time.Time `json:"createdAt"`
    UpdatedAt       time.Time `json:"updatedAt"`
}
```

### API Endpoints

**Get User (with visibility control)**:
```
GET /api/users/me - Your full profile (always complete)
GET /api/users/{id} - Another user's profile (respects visibility settings)
GET /api/public/users/{username} - Public profile view (unauthenticated access OK)
```

**Public Profile Response**:
```json
{
  "id": "user123",
  "username": "alice",
  "displayName": "Alice Smith",
  "bio": "...",                    // Only if isPublicBio=true
  "avatarUrl": "...",              // Only if isPublicAvatar=true
  "followerCount": 42,             // Only if isPublicStats=true
  "followingCount": 15,            // Only if isPublicStats=true
  "isFollowing": true,             // Your follow status (null if anonymous)
  "createdAt": "2024-01-15T..."
}
```

**Update User Settings**:
```
PUT /api/users/me
{
  "displayName": "...",
  "bio": "...",
  "avatarUrl": "...",
  "isPublicBio": true,
  "isPublicAvatar": true,
  "isPublicStats": true
}
```

**Get Public Things**:
```
GET /api/public/users/{username}/things?limit=50&offset=0
- Returns Things where visibility='public'
- Anonymous access allowed
```

**Get Things for Authenticated User**:
```
GET /api/users/{id}/things?limit=50&offset=0
- Returns Things where:
  - visibility='private' AND userId=currentUser (your own)
  - visibility='friends' AND (friendship exists OR userId=currentUser)
  - visibility='public' AND userId={id}
```

### Access Control Logic

**When fetching Things**:
```go
func (a *API) canViewThing(thing *Thing, viewerID string) bool {
    if thing.Visibility == "public" {
        return true
    }
    if thing.Visibility == "private" {
        return thing.UserID == viewerID
    }
    if thing.Visibility == "friends" {
        // Check if viewerID and thing.UserID are friends
        if thing.UserID == viewerID {
            return true
        }
        return a.store.AreFriends(viewerID, thing.UserID)
    }
    return false
}
```

### Store Layer Changes

**Update `store.go`**:
- Add methods to check visibility on Thing retrieval
- Filter results based on visibility in `ListThings()`
- Update User retrieval to respect `isPublic*` fields

### Frontend Changes

**Public Profile Page** (`/public/@{username}`):
- Show username, displayName, createdAt
- Conditionally show: bio, avatar, follower/following counts (based on `isPublic*`)
- Show public Things in paginated list
- Follow/Unfollow button
- List of followers (if public)

**Settings Page Update**:
- Add toggles for `isPublicBio`, `isPublicAvatar`, `isPublicStats`
- Show preview of what public sees

**Visibility Selector for Posts**:
- When creating Thing, choose visibility: private/friends/public
- Show icon/indicator on posts showing visibility level

---

## Phase 3: Friendships & Friend Feed

### Objective
Implement follow system with friend feed, caching, and access control.

### Database Changes

```sql
CREATE TABLE IF NOT EXISTS friendships (
    id TEXT PRIMARY KEY,
    follower_id TEXT NOT NULL,
    following_id TEXT NOT NULL,
    status TEXT CHECK(status IN ('pending', 'accepted', 'blocked')) DEFAULT 'accepted',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(follower_id, following_id),
    FOREIGN KEY(follower_id) REFERENCES users(id),
    FOREIGN KEY(following_id) REFERENCES users(id)
);
CREATE INDEX idx_friendships_follower ON friendships(follower_id, status);
CREATE INDEX idx_friendships_following ON friendships(following_id, status);
```

### Model Changes

**New Friendship Model** (`internal/models/models.go`):
```go
type Friendship struct {
    ID          string    `json:"id"`
    FollowerID  string    `json:"followerId"`   // Person doing the following
    FollowingID string    `json:"followingId"`  // Person being followed
    Status      string    `json:"status"`       // "pending", "accepted", "blocked"
    CreatedAt   time.Time `json:"createdAt"`
    UpdatedAt   time.Time `json:"updatedAt"`
}
```

### API Endpoints

**Follow/Unfollow**:
```
POST /api/users/{id}/follow
- Creates Friendship with status='accepted' (auto-accept for now)
- Allows following private profiles
- Returns: Friendship object

DELETE /api/users/{id}/follow
- Removes Friendship
- You can no longer see their "friends" Things
- Returns: 204 No Content
```

**Manage Followers**:
```
GET /api/users/me/followers?limit=50&offset=0
- List people following you
- Returns: Array of User objects + followerCount, followingCount

DELETE /api/users/me/followers/{followerID}
- Remove a follower (they stop following you)
- Returns: 204 No Content
```

**Manage Following**:
```
GET /api/users/me/following?limit=50&offset=0
- List people you follow
- Returns: Array of User objects

GET /api/users/{id}/followers?limit=50&offset=0
- List people following this user (only if isPublicStats=true)
- Returns: Array of User objects

GET /api/users/{id}/following?limit=50&offset=0
- List people this user follows (only if isPublicStats=true)
- Returns: Array of User objects
```

**Friend Feed**:
```
GET /api/feed/friends?limit=50&offset=0
- Returns Things from people you follow (where visibility='friends' or 'public')
- Always fetches fresh (checks current access control)
- Order by createdAt DESC
- Returns: Array of Thing objects

GET /api/feed/friends/post-ids?limit=50&offset=0
- Returns: { postIds: [...], total: 500 }
- This can be cached (30-60s TTL)
- Invalidate on: new Thing created, Thing deleted, Friendship changed
```

### Store Layer Changes

**Add to `store.go`**:
```go
// Friendship operations
CreateFriendship(friendship *Friendship) error
GetFriendship(followerID, followingID string) (*Friendship, error)
DeleteFriendship(followerID, followingID string) error
ListFollowers(userID string, limit, offset int) ([]User, error)
ListFollowing(userID string, limit, offset int) ([]User, error)
CountFollowers(userID string) (int, error)
CountFollowing(userID string) (int, error)
AreFriends(userID1, userID2 string) (bool, error)
GetFriendFeed(userID string, limit, offset int) ([]Thing, error)
GetFriendFeedPostIDs(userID string, limit, offset int) ([]string, error)
```

### Websocket Manager

**New `internal/websocket/manager.go`**:
```go
type Manager struct {
    mu              sync.RWMutex
    userConnections map[string]*Connection        // userID -> Connection
    friendConnections map[string][]*FriendWS     // userID -> [friends' websockets]
}

type Connection struct {
    UserID string
    Conn   *websocket.Conn
    Send   chan interface{}
}

type FriendWS struct {
    UserID string
    URL    string
    Conn   *websocket.Conn
}

// Methods:
// ConnectToFriends(userID string, friends []User) - Connect outbound to friends' servers
// DisconnectFromFriend(userID, friendID string) - Close connection to specific friend
// BroadcastToFollowers(userID string, event interface{}) - Notify all followers
// HandleClientConnection(userID string) - Accept inbound websocket from follower
// SendEvent(userID string, event interface{}) - Send event to connected client
```

### Websocket Flow

**User Login**:
1. User authenticates via HTTP
2. Server queries: "Who follows this user?"
3. Server connects outbound websockets to each follower's server
4. Server stores these connections in manager

**User Posts Something**:
1. Create Thing in database
2. Query: "Who follows me?"
3. For each follower server, send `thing_created` event via websocket
4. Invalidate follower's feed cache
5. Follower's client receives event, fetches fresh content

**Frontend Connection**:
1. After login, connect websocket to `/ws`
2. Receive events from followed users
3. Listen for: `thing_created`, `friendship_created`, etc.
4. Update UI in real-time

**Friendship Change**:
1. User A follows User B
2. A's server connects websocket to B's server
3. B's server has connection from A, can now notify A of posts
4. A receives updates from B in real-time

### Real-Time Updates via WebSocket

**Architecture: Websocket-per-friendship**

Each user's server maintains outbound websocket connections to their friends' servers. When a friend does something (posts, follows you, etc.), they're notified in real-time.

**Connection Model**:
```
User A's server ──websocket──> User B's server (A follows B)
User A's server ──websocket──> User C's server (A follows C)

User B's server ──websocket──> User A's server (B follows A back)
```

**Memory Overhead**:
- Per connection: ~20-30 KB in Go (goroutines are very lightweight)
- 20 friends = ~400-600 KB total
- On 256MB Fly VM: negligible (<0.3%)
- Could support ~5,000+ friendships on 256MB VM

**Websocket Events**:
```json
// New post from friend
{
  "type": "thing_created",
  "userId": "user456",
  "thing": { "id": "...", "content": "..." }
}

// Friend followed you
{
  "type": "friendship_created",
  "userId": "user456",
  "friendshipId": "..."
}

// Friend removed/unfollowed you
{
  "type": "friendship_deleted",
  "userId": "user456",
  "friendshipId": "..."
}

// Thing deleted by friend
{
  "type": "thing_deleted",
  "userId": "user456",
  "thingId": "..."
}
```

**API Endpoint**:
```
GET /ws - WebSocket upgrade endpoint
- Authenticate via session cookie
- Maintain connection to friend servers
- Receive real-time events
- Send heartbeat/ping-pong frames
```

**Backend Implementation**:
1. When user logs in, connect websockets to all their friends' servers
2. When user posts, notify all followers' servers via their websocket connections
3. Frontend connects to user's server websocket, receives aggregated events
4. On friendship change, establish/close websocket connections

**Caching Strategy**

**Post ID Cache**:
- Key: `friend_feed_post_ids:{userID}:{limit}:{offset}`
- TTL: 30-60 seconds
- Invalidate triggers (via websocket events):
  - New Thing created by any followed user → invalidate feed cache
  - Thing deleted by followed user → invalidate feed cache
  - Friendship status changes → invalidate feed cache
  - You follow/unfollow someone → invalidate feed cache

**Content Fetch**:
- Always fetch Things fresh (don't cache full content)
- This ensures access control is current (if someone unfollows you, you lose access immediately)
- Frontend gets real-time notification via websocket, then fetches fresh content

### Frontend Changes

**Follow Button**:
- Appears on public profiles and user cards
- Shows "Following" / "Follow" state
- Click to follow/unfollow

**Followers/Following Pages**:
- `/users/{username}/followers` - Show list of followers
- `/users/{username}/following` - Show list of following
- Only visible if `isPublicStats=true`

**Friend Feed View**:
- New tab/view in main feed: "Your Feed" | "Friends Feed"
- Shows Things from people you follow
- Paginated with offset
- Mix of their friends/public Things

**Remove Follower**:
- On `/users/me/followers` page
- Show "X" or "Remove" button next to each follower
- Confirmation: "Remove {username} from your followers?"

---

## Implementation Roadmap

### Phase 1: Gallery Photos (Week 1)
- [ ] Update Photo model with caption and order_index
- [ ] Migrate database schema
- [ ] Update photo upload API to handle arrays
- [ ] Update Thing retrieval to include photos
- [ ] Build photo carousel component
- [ ] Test carousel navigation

### Phase 2: Visibility & Public Profiles (Week 2)
- [ ] Add visibility to Thing model and database
- [ ] Add public fields to User model and database
- [ ] Implement access control logic
- [ ] Create public profile API endpoints
- [ ] Build public profile frontend page
- [ ] Add visibility selector to post creation
- [ ] Build settings page for public profile options

### Phase 3: Friendships, WebSocket Real-Time, & Friend Feed (Week 3)
- [ ] Create Friendship model and database table
- [ ] Implement friendship API endpoints
- [ ] Build websocket manager for server-to-server connections
- [ ] Implement websocket endpoint for client connections
- [ ] Add websocket event broadcasting on Thing creation/deletion
- [ ] Add websocket event broadcasting on friendship changes
- [ ] Build follow/unfollow UI
- [ ] Implement friend feed API with caching
- [ ] Build friend feed UI with real-time updates
- [ ] Add followers/following management with websocket sync
- [ ] Test access control on friend feed
- [ ] Test websocket connection/disconnection scenarios

### Phase 4: Polish & Testing (Week 4)
- [ ] End-to-end testing
- [ ] Performance testing on large friend feeds
- [ ] Mobile responsiveness
- [ ] Documentation updates

---

## Technical Notes

### Gallery Thing Structure

When returned from API, a gallery Thing looks like:
```json
{
  "id": "thing123",
  "userId": "user456",
  "type": "gallery",
  "content": "Had an amazing weekend!",
  "visibility": "friends",
  "metadata": {},
  "version": 1,
  "photos": [
    {
      "id": "photo1",
      "thingId": "thing123",
      "caption": "Sunset at the beach",
      "orderIndex": 0,
      "contentType": "image/jpeg",
      "filename": "sunset.jpg",
      "size": 245678,
      "createdAt": "2024-01-15T14:30:00Z"
    },
    {
      "id": "photo2",
      "thingId": "thing123",
      "caption": "Night sky",
      "orderIndex": 1,
      "contentType": "image/jpeg",
      "filename": "night_sky.jpg",
      "size": 189234,
      "createdAt": "2024-01-15T14:30:00Z"
    }
  ],
  "createdAt": "2024-01-15T14:30:00Z",
  "updatedAt": "2024-01-15T14:30:00Z"
}
```

### Visibility Rules Summary

| Visibility | Owner | Friends | Public | Anonymous |
|-----------|-------|---------|--------|-----------|
| private   | ✓     | ✗       | ✗      | ✗         |
| friends   | ✓     | ✓       | ✗      | ✗         |
| public    | ✓     | ✓       | ✓      | ✓         |

### Access Control Summary

**Things visible in your feed**:
1. Your own Things (all visibility levels)
2. Things from people you follow (if visibility='friends' or 'public')
3. Other users' public Things (if visibility='public')

**Removing follower**:
- Person can still see your 'public' Things
- Person can no longer see your 'friends' Things
- Post IDs are cached, but content fetch fails access control check

---

## Future Enhancements

- Pending friendship requests (not auto-accept)
- Block users functionality
- Follower notifications
- Follower-only content tier
- Advanced privacy controls (block specific users from seeing posts)
- Share individual Things with specific friends
- Collaborative galleries

---

## References

- Current code: `internal/models/models.go`, `internal/api/api.go`, `internal/store/store.go`
- Frontend: `web/src/App.tsx`
- Database initialization: `internal/store/store.go` (schema creation)
