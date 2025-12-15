# Friends UI Implementation Plan

## Overview

Add a Friends UI to tenant.social that allows users to follow others and see a feed of their posts.

## Navigation Changes

**Current:** Path-based routing (`/settings`, `/kinds`, `/friends`, `/feed`)

**Main tabs:**
- **Feed** - Posts from people you follow (`/feed`)
- **Profile** - Your posts (current home view) (`/`)
- **Friends** - Manage who you follow (`/friends`)
- (Keep Settings as secondary nav) (`/settings`)

## Friends Tab

### Add Friend Section
- Text input for friend's base URL
- Examples: `bob`, `/bob`, `http://localhost:7777/bob`, `http://tenant.social/alice`
- "Add" button to initiate follow

### Following List
- List of people you follow
- Shows: username, endpoint, follow date
- "Unfollow" button for each

### Followers List
- List of people who follow you (read-only)
- Shows: username, endpoint, follow date

## Feed Tab

- Shows posts from everyone you follow
- Uses existing `GET /api/feed/friends` endpoint
- Same post card UI as Profile view
- Sorted by created_at DESC
- Click post to view on friend's profile (opens in new tab or navigates)

## Follow Flow

1. User enters URL in Friends tab (e.g., `bob`)
2. Frontend normalizes URL:
   - `bob` → `/bob` (same apartment)
   - `/bob` → `/bob`
   - `http://...` → full URL
3. Fetch public profile: `GET {endpoint}/api/public/profile`
4. Extract `user_id` from response
5. Call `POST /api/friends` with:
   ```json
   {
     "remote_user_id": "<user_id from profile>",
     "remote_endpoint": "<normalized endpoint>",
     "access_token": null
   }
   ```
6. Refresh following list on success

## Implementation Steps

### Step 1: Update Navigation
- [x] Add Feed/Profile/Friends tabs to main nav
- [x] Use path-based routing: `/feed`, `/friends`, `/settings`
- [x] Default view is Profile (`/`), Feed at `/feed`

### Step 2: Friends Tab UI
- [x] Create FriendsView component
- [x] Add friend input + button
- [x] Display following list from `GET /api/follows/following`
- [x] Display followers list from `GET /api/follows/followers`
- [x] Unfollow button calls `DELETE /api/follows/{user_id}`

### Step 3: Add Friend Logic
- [x] URL normalization helper
- [x] Fetch remote profile to get user_id
- [x] Call POST /api/friends
- [x] Error handling (user not found, already following, etc.)

### Step 4: Feed Tab UI
- [x] Create FeedView component
- [x] Fetch from `GET /api/feed/friends`
- [x] Render posts using existing Thing card component
- [x] Handle empty state (no friends yet)

### Step 5: Testing
- [ ] Test following user in same apartment
- [ ] Test unfollowing
- [ ] Test feed displays friend posts
- [ ] Test visibility (only friends/public posts shown)

## API Endpoints Used

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/friends` | POST | Follow a user |
| `/api/follows/{user_id}` | DELETE | Unfollow a user |
| `/api/follows/following` | GET | List who you follow |
| `/api/follows/followers` | GET | List who follows you |
| `/api/feed/friends` | GET | Get friend feed |
| `{remote}/api/public/profile` | GET | Get user info for following |

## UI Mockup

```
┌─────────────────────────────────────────────────┐
│  [Feed]  [Profile]  [Friends]      [Settings]   │
├─────────────────────────────────────────────────┤
│                                                 │
│  Add Friend                                     │
│  ┌─────────────────────────┐  ┌───────┐        │
│  │ bob                     │  │  Add  │        │
│  └─────────────────────────┘  └───────┘        │
│                                                 │
│  Following (2)                                  │
│  ┌─────────────────────────────────────────┐   │
│  │ alice @ /alice              [Unfollow]  │   │
│  │ bob @ /bob                  [Unfollow]  │   │
│  └─────────────────────────────────────────┘   │
│                                                 │
│  Followers (1)                                  │
│  ┌─────────────────────────────────────────┐   │
│  │ charlie @ /charlie                      │   │
│  └─────────────────────────────────────────┘   │
│                                                 │
└─────────────────────────────────────────────────┘
```

## Notes

- Ignore mutuals for now (Phase 2)
- Using path-based routing (`/feed`, `/friends`, etc.) with SPA fallback
- Profile is the default view (`/`)
- Feed at `/feed`, Friends at `/friends`
