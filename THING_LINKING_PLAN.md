# Thing Linking Implementation Plan

## Overview

Thing Linking allows Things to reference other Things via unidirectional "link" attributes. A Thing stores the ID of Things it links to, enabling creation of relationships like "photo Kind has a photo Thing attribute" or "article Kind has related-articles Things attribute."

Users can:
1. Create link-type attributes on Kinds
2. When creating/editing Things, select other Things to link to
3. View backlinks - see what other Things link to a specific Thing

## Design Decision: Unidirectional

We're implementing **unidirectional linking** where:
- Only the linking Thing stores the reference (in its metadata)
- Backlinks are discovered by querying all Things, checking their link attributes
- Simple to implement, no consistency issues between sides
- Future: Bidirectional linking (synced on both sides) can be added later with more complexity

### Rationale

Unidirectional avoids:
- Keeping both sides in sync (complex on update/delete)
- Database constraints becoming circular
- User confusion about "which side is the source"

Backlinks are still queryable, just computed on-read rather than pre-stored.

## Implementation Steps

### Step 1: Backend Store - Add GetBacklinks Method

**File**: `internal/store/store.go`

Add to `Store` interface:
```go
// GetBacklinks returns all Things that link to the given Thing
// Scans all user's Things, checks their link attributes for references to targetID
GetBacklinks(userID, targetID string) ([]Thing, error)
```

### Step 2: Backend Store - Implement GetBacklinks in SQLite

**File**: `internal/store/sqlite.go`

Implementation approach:
1. Query all Things for the user
2. Iterate through each Thing's metadata
3. For each Thing, check all attributes for type="link"
4. If link attribute contains targetID, include in results
5. Return matching Things

Pseudocode:
```go
func (s *SQLiteStore) GetBacklinks(userID, targetID string) ([]Thing, error) {
    // Get all Things for user
    things, err := s.GetThings(userID, ThingQuery{})
    if err != nil {
        return nil, err
    }

    var backlinks []Thing
    for _, thing := range things {
        // Check each attribute
        for _, attr := range thing.Attributes {
            if attr.Type == "link" {
                // attr.Value should be a Thing ID or JSON array of IDs
                if contains(attr.Value, targetID) {
                    backlinks = append(backlinks, thing)
                    break // Don't include thing twice
                }
            }
        }
    }

    return backlinks, nil
}
```

### Step 3: API Layer - Add GetBacklinks Handler and Route

**File**: `internal/api/api.go`

Add HTTP handler:
```go
func (a *API) getThingBacklinks(w http.ResponseWriter, r *http.Request) {
    // Extract userID from context (auth middleware)
    // Extract thingID from URL params
    // Call store.GetBacklinks(userID, thingID)
    // Return JSON response: { backlinks: [...] }
}
```

Add route in router setup:
```go
router.HandleFunc("GET /api/things/{id}/backlinks", a.withAuth(a.getThingBacklinks))
```

### Step 4: Frontend - Add Link AttributeInput Type

**File**: `web/src/App.tsx` or `web/src/components/EditThingModal.tsx`

Modify `AttributeInput` component to handle type="link":
1. Fetch available Things for user when component mounts
2. Render searchable dropdown
3. Allow multi-select (link attribute can reference multiple Things)
4. Show selected Things with preview cards
5. Handle add/remove of linked Things

UI Features:
- Search box to filter Things by name
- Display Thing preview (name, kind, thumbnail if photo)
- "Add link" button to select Things
- Remove button (X) for each linked Thing
- Shows existing links on Thing load

### Step 5: Frontend - Display Linked Things and Backlinks

**File**: `web/src/components/ThingView.tsx` or similar

Add two sections in Thing detail view:

**Links Section** (Things this Thing links to):
- Show linked Things (references stored in metadata)
- Render as cards/list with preview images
- Clickable to navigate to linked Thing

**Backlinks Section** (Things that link to this Thing):
- Fetch from `/api/things/{id}/backlinks`
- Display as cards/list
- Show which attribute type links to this Thing
- Clickable to navigate

## Files to Modify

| File | Change | Priority |
|------|--------|----------|
| `internal/store/store.go` | Add GetBacklinks method to Store interface | 1 |
| `internal/store/sqlite.go` | Implement GetBacklinks logic | 1 |
| `internal/api/api.go` | Add getThingBacklinks handler and route | 2 |
| `web/src/App.tsx` or component file | Add "link" case to AttributeInput | 2 |
| `web/src/components/ThingView.tsx` | Add linked Things and backlinks sections | 2 |
| `docs/ROADMAP.md` | Already updated with Thing Linking section | Done |

## Testing Strategy

### Backend Tests

**Store Tests** (`internal/store/sqlite_test.go`):
1. Create 3 Things: A, B, C (user1)
2. Create Thing D with link attribute pointing to A
3. Call GetBacklinks(user1, A.ID) → should return [D]
4. Create Thing E with link to both A and B
5. Call GetBacklinks(user1, A.ID) → should return [D, E]
6. Verify backlinks don't cross users (create Thing in user2, verify not in user1 backlinks)
7. Test link to non-existent Thing (should handle gracefully)
8. Test Thing with multiple link attributes

**API Tests** (`internal/api/api_test.go`):
1. Test `/api/things/{id}/backlinks` endpoint
2. Test auth required
3. Test valid response structure
4. Test with no backlinks (empty array)
5. Test with multiple backlinks

### Frontend Tests

**Component Tests** (`web/playwright.spec.ts`):
1. Open Thing edit modal
2. Add link attribute to Kind
3. Create Thing, add link to another Thing
4. Verify link appears in metadata
5. Navigate to linked Thing
6. Verify backlinks section shows the originating Thing
7. Test removing link from Thing
8. Verify backlinks section updates

## Current Status

- Basic intent documented in ROADMAP.md ✓
- Unidirectional design decided ✓
- This plan created ✓
- Ready to implement: Start with Step 1 (GetBacklinks interface)

## Future: Bidirectional Linking

Once unidirectional is working:
- Store both directions (link + back-link in metadata)
- On create/update: sync both sides
- On delete: remove all backlinks pointing to deleted Thing
- Handle circular references
- Index both directions for performance

Trade-offs:
- More complex code
- Database operations become transactions
- Risk of sync issues if operations fail midway
- Better performance (no scan for backlinks)
- Better UX (instant backlinks without query)
