# Go vs Rust Backend Parity Issues

## Critical Issues (Must Fix)

### 1. Registration Policy
- **Go**: Single-tenant enforcement - rejects registration if ANY user exists (403)
- **Rust**: Allows unlimited user registration
- **Fix**: Add user count check before registration

### 2. First User Admin Status
- **Go**: First registered user becomes admin (`is_admin: true`)
- **Rust**: All users are `is_admin: false`
- **Fix**: Check if first user and set admin flag

### 3. Login Email Support
- **Go**: Accepts username OR email in `username` field (checks for `@`)
- **Rust**: Only accepts username
- **Fix**: Add email lookup fallback in login

### 4. Locked Account Status Code
- **Go**: Returns 401 Unauthorized
- **Rust**: Returns 403 Forbidden
- **Fix**: Change to 401 for consistency

### 5. Auth Status Endpoint
- **Go**: Returns dynamic `hasOwner` and `registrationEnabled` based on user count
- **Rust**: Hardcodes `hasOwner: true`, `registrationEnabled: false`
- **Fix**: Query actual user count

### 6. Response Format Inconsistency
- **Go**: Direct objects for all endpoints
- **Rust**: Mix of ApiResponse wrapper and direct objects
- **Fix**: Standardize on direct objects (remove ApiResponse wrapper from auth/keys)

### 7. API Key List Response
- **Go**: Returns `{ keys: [...], availableScopes: [...] }`
- **Rust**: Returns `{ success: true, data: [...] }`
- **Fix**: Match Go format with availableScopes

### 8. API Key Missing Fields
- **Go**: Supports `metadata` and `expiresAt` fields
- **Rust**: Only `name` and `scopes`
- **Fix**: Add metadata and expiresAt support

---

## Medium Issues

### 9. Update Semantics
- **Go**: Full object replacement on PUT
- **Rust**: Partial update (only provided fields)
- **Decision**: Keep Rust behavior (more flexible), document difference

### 10. Field Naming Convention
- **Go**: camelCase (`keyPrefix`, `createdAt`)
- **Rust**: snake_case (`key_prefix`, `created_at`)
- **Fix**: Use serde rename to output camelCase

---

## Implementation Status

| Issue | Status | PR |
|-------|--------|-----|
| 1. Registration Policy | DONE | Single-tenant enforcement added |
| 2. First User Admin | DONE | First user is_admin=true |
| 3. Login Email Support | DONE | Email login via @ detection |
| 4. Locked Account Status | DONE | Returns 401 (was 403) |
| 5. Auth Status Endpoint | DONE | Dynamic hasOwner/registrationEnabled |
| 6. Response Format | DONE | Removed ApiResponse wrapper |
| 7. API Key List Response | DONE | Returns { keys, availableScopes } |
| 8. API Key Fields | SKIP | Low priority for now |
| 11. Empty Scopes = Admin | DONE | Empty scopes give full access |
| 9. Update Semantics | KEEP AS-IS | Partial update is better UX |
| 10. Field Naming | PARTIAL | Some fields use camelCase |

---

## Testing Checklist

After fixes, verify:
- [ ] Registration fails when user exists (403)
- [ ] First user has `is_admin: true`
- [ ] Can login with email address
- [ ] Locked account returns 401
- [ ] `/api/auth/status` shows correct registration status
- [ ] Auth responses are direct objects (no wrapper)
- [ ] API key list includes `availableScopes`
- [ ] API keys support metadata and expiresAt
- [ ] JSON responses use camelCase
