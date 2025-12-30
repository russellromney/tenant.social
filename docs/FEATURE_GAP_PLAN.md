# Rust Backend Feature Gap Plan

## Overview

This document tracks the features present in the Go backend that need to be implemented in the Rust backend to achieve feature parity.

**Current Status:**
- Go: Production backend with full feature set
- Rust: Development backend with notifications, reactions, federation, metrics

---

## Priority 1: Core Missing Features

### 1.1 User Profile Management
| Endpoint | Method | Description | Complexity |
|----------|--------|-------------|------------|
| `/api/auth/check` | GET | Check if user is authenticated | Low |
| `/api/auth/me` | PUT | Update user profile (display_name, bio, avatar) | Low |

### 1.2 API Keys - Full CRUD
| Endpoint | Method | Description | Complexity |
|----------|--------|-------------|------------|
| `/api/keys/{id}` | GET | Get single API key details | Low |
| `/api/keys/{id}` | PUT | Update API key (name, scopes) | Low |

### 1.3 Things - Version History
| Endpoint | Method | Description | Complexity |
|----------|--------|-------------|------------|
| `/api/things/{id}/versions` | GET | List all versions of a thing | Medium |
| `/api/things/{id}/versions/{version}` | GET | Get specific version | Medium |
| `/api/things/{id}/versions/{version}/revert` | POST | Revert to a previous version | Medium |
| `/api/things/{id}/restore` | POST | Restore a soft-deleted thing | Low |

**Implementation Notes:**
- `thing_versions` table already exists in schema
- Need to create version on every update
- Revert creates a new version with old content

---

## Priority 2: Bulk Operations

### 2.1 Bulk Thing Operations
| Endpoint | Method | Description | Complexity |
|----------|--------|-------------|------------|
| `/api/things/bulk` | POST | Create multiple things at once | Medium |
| `/api/things/bulk` | PUT | Update multiple things at once | Medium |
| `/api/things/bulk` | DELETE | Delete multiple things at once | Medium |
| `/api/things/upsert` | PUT | Create or update a thing by ID | Low |

**Implementation Notes:**
- Use transactions for atomicity
- Return partial success/failure info
- Limit batch size (e.g., max 100 items)

---

## Priority 3: Search & Query

### 3.1 Search Endpoints
| Endpoint | Method | Description | Complexity |
|----------|--------|-------------|------------|
| `/api/things/search` | GET | Full-text search across things | High |
| `/api/things/query` | GET | Advanced query with filters | Medium |

**Implementation Notes:**
- SQLite FTS5 for full-text search
- Query supports: type, visibility, date range, kind, tags
- Consider pagination and result limits

---

## Priority 4: Tags System

### 4.1 Tags CRUD
| Endpoint | Method | Description | Complexity |
|----------|--------|-------------|------------|
| `/api/tags` | GET | List all tags for user | Low |
| `/api/tags` | POST | Create a new tag | Low |
| `/api/tags/{id}` | PUT | Update tag | Low |
| `/api/tags/{id}` | DELETE | Delete tag | Low |

**Implementation Notes:**
- Tags table exists in schema
- Many-to-many relationship via `thing_tags` table
- Need to add tag assignment to things endpoints

---

## Priority 5: Views System

### 5.1 Views CRUD
| Endpoint | Method | Description | Complexity |
|----------|--------|-------------|------------|
| `/api/views` | GET | List saved views | Low |
| `/api/views` | POST | Create a view | Low |
| `/api/views/{id}` | GET | Get view details | Low |
| `/api/views/{id}` | PUT | Update view | Low |
| `/api/views/{id}` | DELETE | Delete view | Low |

**Implementation Notes:**
- Views are saved filter/sort configurations
- Schema: id, user_id, name, config (JSON), created_at, updated_at
- Config contains: filters, sort, display options

---

## Priority 6: Photo Management

### 6.1 Photo Operations
| Endpoint | Method | Description | Complexity |
|----------|--------|-------------|------------|
| `/api/photos/{id}` | PUT | Update photo metadata | Low |
| `/api/photos/{id}` | DELETE | Delete photo | Medium |

**Implementation Notes:**
- Delete should remove from S3/storage
- Update allows changing caption, order, etc.
- Consider soft delete vs hard delete

---

## Priority 7: Data Portability

### 7.1 Export/Import
| Endpoint | Method | Description | Complexity |
|----------|--------|-------------|------------|
| `/api/export` | GET | Export all user data as JSON/ZIP | High |
| `/api/import` | POST | Import data from export file | High |

**Implementation Notes:**
- Export: things, kinds, tags, photos, settings
- Format: JSON with embedded base64 images or ZIP with files
- Import: validate, deduplicate, handle conflicts

---

## Priority 8: Admin Features

### 8.1 Admin Endpoints
| Endpoint | Method | Description | Complexity |
|----------|--------|-------------|------------|
| `/api/admin/users` | GET | List all users (admin only) | Low |
| `/api/admin/users/{id}` | GET | Get user details | Low |
| `/api/admin/users/{id}` | PUT | Update user (lock, admin status) | Low |
| `/api/admin/users/{id}` | DELETE | Delete user | Medium |

**Implementation Notes:**
- Require `is_admin` check
- User deletion should cascade or archive

---

## Implementation Order

```
Phase 1 (Quick Wins):
├── auth/check
├── auth/me PUT
├── keys/{id} GET/PUT
└── things/{id}/restore

Phase 2 (Version History):
├── things/{id}/versions GET
├── things/{id}/versions/{v} GET
└── things/{id}/versions/{v}/revert

Phase 3 (Bulk Operations):
├── things/bulk POST/PUT/DELETE
└── things/upsert

Phase 4 (Search):
├── things/search
└── things/query

Phase 5 (Tags & Views):
├── tags CRUD
└── views CRUD

Phase 6 (Photos & Export):
├── photos/{id} PUT/DELETE
├── export
└── import

Phase 7 (Admin):
└── admin/* endpoints
```

---

## Estimated Effort

| Phase | Endpoints | Estimated Effort |
|-------|-----------|------------------|
| Phase 1 | 5 | 1-2 hours |
| Phase 2 | 3 | 2-3 hours |
| Phase 3 | 4 | 2-3 hours |
| Phase 4 | 2 | 3-4 hours |
| Phase 5 | 9 | 2-3 hours |
| Phase 6 | 4 | 4-6 hours |
| Phase 7 | 4 | 1-2 hours |
| **Total** | **31** | **15-23 hours** |

---

## Testing Requirements

Each new endpoint needs:
1. Unit tests for store/database operations
2. Integration tests for API endpoints
3. Auth/scope verification tests
4. Error handling tests

---

## Notes

- All endpoints should follow existing patterns in `src/api/mod.rs`
- Use existing `ApiResponse` wrapper for consistency
- Scope checks should match Go implementation
- Database operations go in `src/store/mod.rs`
