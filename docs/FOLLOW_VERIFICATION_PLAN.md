# Follow Verification Flow Plan

## Overview
Implement a mutual verification handshake for federated follows to prevent fake/bot follows and prove identity across instances.

## Key Principles
- Authentication happens locally (users stay logged in on their own instance)
- Follow tokens are ephemeral and single-purpose (expires in minutes)
- Remote instances can verify a follow request came from a real, authenticated user
- Mutual verification ensures both sides know the follow is legitimate

## Flow

### 1. User Creates Follow Token (Local)
**Endpoint:** `POST /api/follows/create-token`
- **Auth Required:** Yes (user must be logged in)
- **Request:** Empty body
- **Response:**
  ```json
  {
    "follow_token": "abc123...",
    "expires_in": 300
  }
  ```
- **Details:**
  - Token is JWT or opaque string
  - Expires in 5 minutes
  - Scoped only for "follow" action
  - Includes user_id and instance URL
  - Cannot be used to read/write content

### 2. User Sends Follow Request to Remote Instance
**Endpoint:** `POST /api/fed/notify-follow` (on remote instance)
- **Auth Required:** No (public endpoint)
- **Request:**
  ```json
  {
    "follower_user_id": "user123",
    "follower_endpoint": "https://russ.tenant.social",
    "follow_token": "abc123..."
  }
  ```
- **Processing:**
  1. Remote receives request
  2. Remote calls back to verify token (step 3)
  3. If verification passes, create follow record
  4. Return 200 OK
  5. Local instance sees 200, marks follow as confirmed

### 3. Remote Verifies Follow Token
**Endpoint:** `POST /api/fed/verify-follow` (on follower's instance)
- **Auth Required:** No (public endpoint)
- **Request:**
  ```json
  {
    "follow_token": "abc123..."
  }
  ```
- **Response (Valid):**
  ```json
  {
    "valid": true,
    "user_id": "user123",
    "endpoint": "https://russ.tenant.social"
  }
  ```
- **Response (Invalid):**
  ```json
  {
    "valid": false
  }
  ```
- **Details:**
  - Checks if token exists, is not expired, is valid
  - Returns minimal info (user_id + endpoint)
  - No sensitive data in response

## Data Model

### Follow Token (In-Memory or Redis)
```rust
pub struct FollowToken {
    pub token: String,           // The actual token
    pub user_id: String,
    pub endpoint: String,        // This instance's URL
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}
```

## Implementation Steps

1. **Backend - Add Follow Token Management**
   - Add `create_follow_token()` to store (in-memory cache or DB)
   - Add `verify_follow_token()` to check validity
   - Add token cleanup for expired tokens

2. **Backend - Add API Endpoints**
   - `POST /api/follows/create-token` - Create ephemeral token
   - `POST /api/fed/verify-follow` - Verify token from remote instance
   - Update `POST /api/fed/notify-follow` - Record follower with token verification

3. **Backend - Update add_friend Logic**
   - Get follow token before making request
   - Include token in notify-follow request
   - Handle 200/error responses

4. **Frontend - Update Follow UI**
   - When user clicks follow, first call `/api/follows/create-token`
   - Then call remote's `/api/fed/notify-follow` with token
   - Show status (pending → confirmed or error)

5. **Add Tests**
   - Test token creation and expiration
   - Test token verification with valid/invalid tokens
   - Test full follow handshake flow
   - Test expired tokens are rejected

## Test Cases

### Token Creation Tests

#### 1. `test_create_follow_token_authenticated`
- **Setup:** User is logged in
- **Action:** `POST /api/follows/create-token`
- **Expected:**
  - Status: 200
  - Response contains `follow_token` (non-empty string)
  - Response contains `expires_in: 300` (5 minutes)
  - Token can be parsed/verified

#### 2. `test_create_follow_token_unauthenticated`
- **Setup:** User is NOT logged in
- **Action:** `POST /api/follows/create-token` without auth
- **Expected:**
  - Status: 401 Unauthorized
  - No token returned

#### 3. `test_multiple_tokens_per_user`
- **Setup:** User is logged in
- **Action:** Call `POST /api/follows/create-token` twice
- **Expected:**
  - Both calls succeed
  - Both tokens are different
  - Both tokens are valid independently

#### 4. `test_token_contains_user_id`
- **Setup:** User is logged in with user_id = "alice"
- **Action:** `POST /api/follows/create-token`
- **Expected:**
  - Token can be decoded/verified
  - Token contains user_id "alice"
  - Token contains endpoint URL

### Token Verification Tests

#### 5. `test_verify_valid_token`
- **Setup:** Valid token just created
- **Action:** `POST /api/fed/verify-follow` with valid token
- **Expected:**
  - Status: 200
  - Response: `{ "valid": true, "user_id": "alice", "endpoint": "https://alice.example.com" }`

#### 6. `test_verify_invalid_token`
- **Setup:** Token is malformed/fabricated
- **Action:** `POST /api/fed/verify-follow` with invalid token
- **Expected:**
  - Status: 200 (still 200, don't leak info via status codes)
  - Response: `{ "valid": false }`

#### 7. `test_verify_expired_token`
- **Setup:** Token was created 6 minutes ago (past 5 minute expiry)
- **Action:** `POST /api/fed/verify-follow` with expired token
- **Expected:**
  - Status: 200
  - Response: `{ "valid": false }`

#### 8. `test_verify_nonexistent_token`
- **Setup:** Token never created
- **Action:** `POST /api/fed/verify-follow` with random string
- **Expected:**
  - Status: 200
  - Response: `{ "valid": false }`

#### 9. `test_verify_token_once_consumed`
- **Setup:** Token was verified once successfully
- **Action:** Call `POST /api/fed/verify-follow` again with same token
- **Expected:**
  - Status: 200
  - Response: `{ "valid": false }` (one-time use) OR `{ "valid": true }` (reusable for 5 mins)
  - **Note:** Decide based on design - reusable is simpler (remote can retry), one-time is more secure

### Full Follow Handshake Tests

#### 10. `test_complete_follow_flow_success`
- **Setup:**
  - Alice is logged in on alice.example.com
  - Bob exists on bob.example.com
- **Action:**
  1. Alice calls `POST /api/follows/create-token` → gets token_abc
  2. Alice calls `POST bob.example.com/api/fed/notify-follow` with token_abc
  3. Bob's server calls back `POST alice.example.com/api/fed/verify-follow` with token_abc
  4. Alice's server responds with `{ "valid": true, ... }`
  5. Bob's server creates follow record, responds 200
  6. Alice's server marks follow as confirmed
- **Expected:**
  - Alice sees Bob in her `following` list
  - Bob sees Alice in his `followers` list
  - Both have `last_confirmed_at` set

#### 11. `test_follow_fails_remote_verification_fails`
- **Setup:** Same as above, but Alice's verify endpoint is down
- **Action:** Alice initiates follow to Bob
- **Expected:**
  - Bob's notify-follow request fails or times out
  - Bob does NOT create follow record
  - Alice sees error "Could not verify with remote instance"

#### 12. `test_follow_fails_expired_token`
- **Setup:**
  1. Alice creates token
  2. Waits 6 minutes
  3. Tries to follow Bob
- **Expected:**
  - Bob's verify-follow call returns `{ "valid": false }`
  - Bob does NOT create follow record
  - Alice sees error "Token expired, please try again"

#### 13. `test_follow_fails_remote_rejects_follow`
- **Setup:** Bob's `/api/fed/notify-follow` endpoint rejects the request (returns 400)
- **Action:** Alice tries to follow Bob
- **Expected:**
  - Alice sees error "Remote instance rejected follow request"
  - No follow record on either side

#### 14. `test_follow_different_instances_with_different_versions`
- **Setup:**
  - Alice on version 1.0.0
  - Bob on version 2.0.0
- **Action:** Alice follows Bob
- **Expected:**
  - Follow succeeds (versions are compatible enough)
  - Different endpoint formats don't break flow

### Error Cases & Edge Cases

#### 15. `test_token_with_special_characters`
- **Setup:** Token contains special chars (JWT format)
- **Action:** URL-encode and send in request
- **Expected:**
  - Verification works correctly
  - Special chars don't break parsing

#### 16. `test_follow_same_user_twice`
- **Setup:** Alice already follows Bob
- **Action:** Alice tries to follow Bob again with new token
- **Expected:**
  - Status: 409 Conflict (or 400 Bad Request)
  - Error: "Already following this user"
  - No duplicate follow record

#### 17. `test_follow_yourself`
- **Setup:** Alice's endpoint is alice.example.com
- **Action:** Alice tries to follow alice.example.com
- **Expected:**
  - Status: 400 Bad Request
  - Error: "Cannot follow yourself"

#### 18. `test_concurrent_token_creation`
- **Setup:** User creates multiple tokens simultaneously
- **Action:** User makes 5 concurrent `POST /api/follows/create-token` requests
- **Expected:**
  - All 5 succeed
  - All 5 tokens are different and valid
  - No race conditions

#### 19. `test_malicious_token_tampering`
- **Setup:** Attacker modifies a valid token (changes payload)
- **Action:** `POST /api/fed/verify-follow` with tampered token
- **Expected:**
  - Status: 200
  - Response: `{ "valid": false }`
  - Signature validation fails

#### 20. `test_token_from_wrong_user`
- **Setup:**
  - Alice creates token on alice.example.com
  - Bob tries to use Alice's token
- **Action:** Bob's instance calls `POST alice.example.com/api/fed/verify-follow` with Alice's token
- **Expected:**
  - Status: 200
  - Response: `{ "valid": true, "user_id": "alice", "endpoint": "..." }`
  - **Note:** This is expected - token proves Alice is real, Bob's follow is from Alice not Bob
  - (Bob should not be able to create a token for Alice)

### Integration Tests

#### 21. `test_federation_follow_round_trip`
- **Setup:** Two real instances running
- **Action:** Follow from one to the other, then unfollow
- **Expected:**
  - Follow succeeds with all verification steps
  - Follow appears in both directions
  - Unfollow works correctly

#### 22. `test_load_many_tokens`
- **Setup:** Create 1000 tokens over time
- **Action:** Verify old and new tokens
- **Expected:**
  - Recent tokens verify successfully
  - Very old tokens (>5 mins) fail verification
  - System doesn't run out of memory

## Security Considerations

- ✅ Tokens expire quickly (5 minutes)
- ✅ Tokens are single-purpose (follow only)
- ✅ Tokens encode instance origin
- ✅ Verification endpoint is public but validates token
- ✅ Remote can't forge a valid token
- ✅ Local auth token never shared across instances
- ✅ Token tampering detected via signature validation
- ✅ Verification responses don't leak different info for valid vs invalid tokens

## Error Cases

1. **Token creation fails** → User not logged in
2. **Token expired** → Asks user to create new token
3. **Remote verification fails** → Follow not created, show error
4. **Remote never responds** → Timeout, follow not created
5. **Remote responds with 500** → Follow not created, retry later

## Future Enhancements

- Implement token revocation (user can invalidate old tokens)
- Rate limit token creation per user
- Log all follow verification attempts
- Add metrics for follow success/failure rates
