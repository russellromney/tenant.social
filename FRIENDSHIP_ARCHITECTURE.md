# Friendship Architecture for tenant.social

## Overview

tenant.social uses a **unidirectional auto-accept following model** optimized for VMs that shut down after 5 minutes of idle time. The architecture prioritizes cost efficiency through aggressive VM shutdown while providing a good user experience through hybrid real-time/polling.

## Core Design Principles

1. **Unidirectional Following**: Users can follow others without requiring approval (Twitter/Mastoday model)
2. **Auto-Accept**: No friend request approval flow - follows happen immediately
3. **Mutual Follower Detection**: Track when A follows B AND B follows A
4. **Privacy-Aware**: Only mutual followers can see each other's online status
5. **VM Shutdown Optimized**: Architecture works perfectly when friend VMs are down

## Database Schema

### Follows Table
```sql
CREATE TABLE follows (
    id TEXT PRIMARY KEY,
    follower_id TEXT NOT NULL,     -- User who is following
    following_id TEXT NOT NULL,     -- User being followed
    created_at TIMESTAMP NOT NULL,
    FOREIGN KEY (follower_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (following_id) REFERENCES users(id) ON DELETE CASCADE,
    UNIQUE(follower_id, following_id)
);

CREATE INDEX idx_follows_follower ON follows(follower_id);
CREATE INDEX idx_follows_following ON follows(following_id);
```

### Detection of Mutual Followers
Two users are mutual followers when:
- EXISTS: follower_id = A AND following_id = B
- EXISTS: follower_id = B AND following_id = A

## API Endpoints

### Follow Management
- `POST /api/follows/{user_id}` - Follow a user (auto-accept)
- `DELETE /api/follows/{user_id}` - Unfollow a user
- `GET /api/follows/followers` - Get list of followers
- `GET /api/follows/following` - Get list of users you follow
- `GET /api/follows/mutuals` - Get mutual followers only

### Friend Feed
- `GET /api/feed/friends` - Get recent things from followed users (visibility: friends or public)
  - Only includes content from users you follow
  - Only includes content with visibility = 'friends' or 'public'
  - Sorted by created_at DESC

### Online Status (Mutual Followers Only)
- `GET /api/follows/mutuals/online` - Get online status of mutual followers
  - Returns list of mutual follower IDs who are currently online
  - Only works for mutual followers (bidirectional relationship)

## Real-Time Architecture

### Hybrid WebSocket + Polling Model

**Problem**: VMs shut down after 5 minutes idle. WebSockets require both VMs to be running.

**Solution**: Opportunistic WebSocket with polling fallback.

#### When Friend's VM is Running
1. User's VM establishes WebSocket to friend's VM via hypervisor proxy
2. Receives real-time updates for new posts, online status changes
3. Updates UI immediately

#### When Friend's VM is Shut Down
1. WebSocket connection fails or times out
2. Fall back to polling every 30 seconds: `GET /api/feed/friends?since={last_check}`
3. Hypervisor starts friend's VM on-demand when polling request arrives
4. Friend's VM serves the feed and shuts down after timeout

#### Online Status Visibility
- Online status is ONLY visible to mutual followers
- When user A goes online, notify all mutual followers who are currently online
- When checking online status, only return mutuals who are online
- Non-mutual followers cannot see your online status

### Connection Flow

```
User A's VM                 Hypervisor              User B's VM
     |                           |                        |
     |---- WS connect to B ----->|                        |
     |                           |---- Start B's VM ----->|
     |                           |                        |
     |<--------- WS connected ----------------->
     |                           |                        |
     |                     (B's VM idles)                 |
     |                           |<----- Shutdown --------|
     |                           |                        |
     |---- Poll /api/feed ------>|                        |
     |                           |---- Start B's VM ----->|
     |                           |<----- Feed data -------|
     |<----- Feed data ----------|                        |
     |                           |                        |
```

## Privacy Model

### Visibility Levels
- `private`: Only visible to the owner
- `friends`: Visible to followers (anyone who follows you)
- `public`: Visible to everyone

### Friend Feed Rules
When user A views their friend feed:
1. Only include posts from users that A follows
2. Include posts with visibility = 'friends' OR 'public'
3. Exclude posts with visibility = 'private'

### Online Status Rules
User A can see user B's online status ONLY if:
- A follows B AND B follows A (mutual followers)

## Cost Optimization

### Aggressive VM Shutdown
- VMs shut down after 5 minutes of no activity
- Polling every 30 seconds is acceptable UX/cost tradeoff
- Real-time WebSocket is opportunistic bonus when both VMs happen to be up

### On-Demand Startup
- Hypervisor starts VMs when needed (on friend feed request, follow request, etc.)
- VMs report readiness via callback
- First request after startup has slightly higher latency (6-8 seconds cold start)

### Caching Strategy
- Cache friend lists in requesting user's VM
- Refresh on follow/unfollow events
- Cache mutual follower status (invalidate on follow/unfollow)
- Cache recent friend feed items (30 second TTL)

## Implementation Phases

### Phase 1: Database & Core Follow API
- Add follows table migration
- Implement follow/unfollow endpoints
- Implement followers/following/mutuals list endpoints
- Add mutual follower detection queries

### Phase 2: Friend Feed
- Implement friend feed query (respects visibility)
- Add pagination support
- Add "since" timestamp for polling efficiency
- Test with VMs shutting down

### Phase 3: Frontend UI
- Add follow/unfollow buttons on user profiles
- Add followers/following lists page
- Add friend feed view
- Add visibility toggle on post creation (private/friends/public)

### Phase 4: Real-Time Features
- Add WebSocket connection management
- Implement hybrid WebSocket + polling
- Add online status for mutual followers
- Add real-time post notifications (opportunistic)

## Security Considerations

### Authorization
- Users can only follow/unfollow as themselves (check JWT)
- Users can only see friend feed for users they follow
- Users can only see online status of mutual followers
- Respect visibility levels on all queries

### Rate Limiting
- Limit follow/unfollow actions (prevent spam)
- Limit polling frequency (30 second minimum between requests)
- Limit WebSocket reconnection attempts

## Testing Strategy

1. **VM Shutdown Scenarios**: Test that friend feed works when friend VMs are down
2. **Mutual Follower Detection**: Test bidirectional vs unidirectional relationships
3. **Visibility Enforcement**: Test that private posts never appear in friend feeds
4. **Online Status Privacy**: Test that non-mutuals cannot see online status
5. **Polling Fallback**: Test graceful degradation when WebSocket fails
