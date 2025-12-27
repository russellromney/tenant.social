# Comment System Test Cases Analysis

## Current Test Coverage

Currently, we have **317 passing tests** but **ZERO tests** for the new comment system endpoints. Here's a comprehensive analysis of test cases that should exist:

---

## 1. Comment Token Creation Tests (Local)

### ✅ Positive Cases
- `test_create_comment_token_authenticated` - User creates token, returns valid token with 5min expiry
- `test_create_comment_token_returns_correct_expiry` - Token has exactly 300 seconds expiry
- `test_create_comment_token_includes_user_id_and_endpoint` - Token response includes commenter's user_id and endpoint
- `test_create_comment_token_returns_unique_tokens` - Each token creation generates unique token

### ❌ Negative Cases
- `test_create_comment_token_unauthenticated` - Returns 401 without auth token
- `test_create_comment_token_with_invalid_token` - Returns 401 with malformed Bearer token
- `test_create_comment_token_with_expired_token` - Returns 401 with expired auth token

### ⚠️ Edge Cases
- `test_create_comment_token_concurrent_creation` - 50+ concurrent requests generate unique tokens
- `test_create_comment_token_rapid_succession` - 100 tokens created in <100ms remain unique

---

## 2. Comment Token Verification Tests (Federation)

### ✅ Positive Cases
- `test_verify_comment_token_valid` - Valid token returns `valid: true` with user_id/endpoint
- `test_verify_comment_token_valid_until_expiry` - Token valid until exact expiry moment
- `test_verify_comment_token_expired_just_after_expiry` - Token invalid 1ms after expiry
- `test_verify_comment_token_payload_accuracy` - Returns correct user_id and endpoint from token

### ❌ Negative Cases
- `test_verify_comment_token_invalid_format` - Malformed token returns `valid: false`
- `test_verify_comment_token_nonexistent` - Random UUID returns `valid: false`
- `test_verify_comment_token_empty_string` - Empty token returns `valid: false`

### ⚠️ Edge Cases
- `test_verify_comment_token_max_length` - Token at 1024 char limit still verifies
- `test_verify_comment_token_oversized_request` - Token >1024 chars returns invalid
- `test_verify_comment_token_special_characters` - Tokens with special chars verify correctly
- `test_verify_comment_token_whitespace_handling` - Whitespace in token fails validation

### 🔒 Security Cases
- `test_verify_comment_token_tampered_token` - Modified token returns `valid: false`
- `test_verify_comment_token_no_information_leakage` - Invalid token doesn't reveal why it's invalid
- `test_verify_comment_token_always_returns_200` - Should never return 4xx (timing attack prevention)

---

## 3. Federated Comment Creation Tests (`/api/fed/comments`)

### ✅ Positive Cases
- `test_notify_comment_valid_federated_comment` - Remote comment creates Thing with type="comment"
- `test_notify_comment_creates_metadata_structure` - Comment has root_id, parent_id, depth in metadata
- `test_notify_comment_sets_correct_visibility` - Federated comment inherits parent visibility
- `test_notify_comment_emits_event` - `comment.created` event emitted to notification system
- `test_notify_comment_returns_success` - Returns 200 OK on valid comment
- `test_notify_comment_multiple_comments_same_post` - Multiple comments on same post all created
- `test_notify_comment_federated_user_attribution` - Comment attributed to remote user_id

### ❌ Negative Cases - Input Validation
- `test_notify_comment_missing_commenter_user_id` - Returns 400 if commenter_user_id empty
- `test_notify_comment_missing_commenter_endpoint` - Returns 400 if commenter_endpoint empty
- `test_notify_comment_missing_thing_id` - Returns 400 if thing_id empty
- `test_notify_comment_missing_content` - Returns 400 if content empty (or allow empty?)
- `test_notify_comment_missing_token` - Returns 400 if comment_token empty
- `test_notify_comment_commenter_user_id_too_long` - Returns 400 if >255 chars
- `test_notify_comment_commenter_endpoint_too_long` - Returns 400 if >2048 chars
- `test_notify_comment_token_too_long` - Returns 400 if >1024 chars
- `test_notify_comment_invalid_endpoint_format` - Returns 400 if not http:// or https://
- `test_notify_comment_endpoint_without_protocol` - Returns 400 for "example.com" (no http)
- `test_notify_comment_endpoint_with_ftp` - Returns 400 for ftp:// (not http/https)

### ❌ Negative Cases - Token Verification
- `test_notify_comment_invalid_token` - Returns 400 if token verification fails
- `test_notify_comment_expired_token` - Returns 400 if token expired
- `test_notify_comment_token_from_different_instance` - Returns 400 if token endpoint mismatch
- `test_notify_comment_token_verification_timeout` - Handles timeout gracefully (return 400)
- `test_notify_comment_token_verification_network_error` - Handles connection error gracefully

### ❌ Negative Cases - Thing Validation
- `test_notify_comment_nonexistent_thing` - Returns 400 if thing_id doesn't exist
- `test_notify_comment_deleted_thing` - Returns 400 if comment target was deleted (or allow?)
- `test_notify_comment_private_thing` - Returns 400 if trying to comment on private post
- `test_notify_comment_friends_only_thing` - Returns 400 if commenter not in friends list (or allow?)

### ⚠️ Edge Cases
- `test_notify_comment_very_long_content` - 10MB comment content (boundary testing)
- `test_notify_comment_empty_string_content` - Empty string as content (should allow?)
- `test_notify_comment_unicode_content` - Emoji, CJK, RTL text in comment
- `test_notify_comment_html_in_content` - HTML tags in content (stored as plaintext)
- `test_notify_comment_json_in_content` - JSON structure in content (escaped properly)
- `test_notify_comment_null_bytes_in_content` - Null bytes handled safely
- `test_notify_comment_sql_injection_attempt` - SQL in content stored as plaintext
- `test_notify_comment_with_metadata` - Custom metadata in comment preserved
- `test_notify_comment_metadata_overflow` - Very large metadata object (10MB)
- `test_notify_comment_concurrent_comments_same_post` - 50 concurrent comments all created

### 🔒 Security Cases
- `test_notify_comment_malicious_token_verification_url` - Endpoint validation prevents XXE/SSRF
- `test_notify_comment_follows_own_instance_protection` - Can't comment on own instance post (or can?)
- `test_notify_comment_spoofed_commenter_id` - Can't impersonate different user on remote instance
- `test_notify_comment_replay_attack` - Same token can't be reused (if implemented)
- `test_notify_comment_rate_limiting` - 1000 comments/sec throttled (if implemented)

---

## 4. Local Comment Creation Tests (`POST /api/things/:id/comments`)

### ✅ Positive Cases
- `test_create_local_comment_success` - Authenticated user creates comment on own Thing
- `test_create_local_comment_on_others_thing` - Can comment on public Things from other users
- `test_create_local_comment_metadata_structure` - Local comment has root_id, parent_id, depth
- `test_create_local_comment_sets_visibility` - Local comment inherits Thing visibility
- `test_create_local_comment_returns_created_thing` - Returns 201 with created Thing object
- `test_create_local_comment_preserves_visibility` - Public post → public comment
- `test_create_local_comment_on_friends_thing` - Can comment on friends-visibility Thing

### ❌ Negative Cases
- `test_create_local_comment_unauthenticated` - Returns 401 without auth
- `test_create_local_comment_nonexistent_thing` - Returns 404 if thing_id doesn't exist
- `test_create_local_comment_on_private_thing` - Returns 403 if trying to comment on private post
- `test_create_local_comment_empty_content` - Returns 400 if content empty (or allow?)
- `test_create_local_comment_thing_missing_scope` - Returns 403 if missing things:write scope

### ⚠️ Edge Cases
- `test_create_local_comment_very_long_content` - 10MB comment (storage limit)
- `test_create_local_comment_unicode_content` - Unicode, emoji, multilingual content
- `test_create_local_comment_html_content` - HTML stored as plaintext
- `test_create_local_comment_concurrent_creation` - Multiple comments created simultaneously

---

## 5. Comment Retrieval Tests (`GET /api/things/:id/comments`)

### ✅ Positive Cases
- `test_get_comments_for_thing_empty` - Returns empty list for Thing with no comments
- `test_get_comments_for_thing_single` - Returns single comment
- `test_get_comments_for_thing_multiple` - Returns multiple comments in creation order
- `test_get_comments_includes_metadata` - Returns root_id, parent_id, depth in metadata
- `test_get_comments_includes_deleted_at` - Tombstoned comments included with deleted_at timestamp
- `test_get_comments_includes_author` - Comment includes user_id/author information
- `test_get_comments_excludes_filtered_deleted` - Only returns deleted comments if requested explicitly (or always?)

### ❌ Negative Cases
- `test_get_comments_nonexistent_thing` - Returns 404 if thing doesn't exist
- `test_get_comments_private_thing_unauthorized` - Returns 403 if user can't view post

### ⚠️ Edge Cases
- `test_get_comments_1000_comments` - Returns all 1000+ comments (or paginate?)
- `test_get_comments_pagination` - Supports limit/offset parameters
- `test_get_comments_sort_order` - Returns in creation order (or configurable?)
- `test_get_comments_with_mixed_visibility` - Comments inherit parent visibility

---

## 6. Comment Depth Validation Tests

### ✅ Positive Cases
- `test_comment_depth_level_0` - Top-level comment (parent_id = root_id, depth = 0)
- `test_comment_depth_level_1` - Reply to comment (parent_id = comment, depth = 1)
- `test_comment_depth_level_2` - Reply to reply (depth = 2)
- `test_comment_depth_level_3` - 4-level deep thread (depth = 3, max allowed)
- `test_comment_depth_preserves_root_id` - root_id stays consistent through all depths

### ❌ Negative Cases
- `test_comment_depth_exceeds_max` - Returns 400 if depth would exceed 3 (4th level)
- `test_comment_reply_to_nonexistent_comment` - Returns 404 if parent doesn't exist
- `test_comment_invalid_parent_id` - Returns 400 if parent_id format invalid

### ⚠️ Edge Cases
- `test_comment_depth_orphaned_parent` - What if parent deleted? (keep or remove?)
- `test_comment_depth_circular_reference` - Can't set parent_id = own id
- `test_comment_depth_cross_thing_parent` - parent_id must be on same root_id

---

## 7. Comment Deletion Tests

### ✅ Positive Cases
- `test_delete_comment_by_author` - Comment author can delete own comment
- `test_delete_comment_by_thing_owner` - Thing owner can delete comments on their post
- `test_delete_comment_sets_deleted_at` - Deletion sets deleted_at timestamp
- `test_delete_comment_preserves_metadata` - Metadata still accessible after deletion
- `test_delete_comment_tombstone_rendering` - Deleted comments show [deleted] in responses
- `test_delete_comment_thread_preserved` - Replies to deleted comment still visible

### ❌ Negative Cases
- `test_delete_comment_unauthorized_user` - Returns 403 if not author or post owner
- `test_delete_comment_nonexistent` - Returns 404 if comment doesn't exist
- `test_delete_comment_already_deleted` - Returns 400 if already deleted (idempotent or error?)
- `test_delete_comment_unauthenticated` - Returns 401 without auth token

### ⚠️ Edge Cases
- `test_delete_comment_soft_delete_only` - Deletion doesn't actually remove row
- `test_delete_comment_restore` - Can undelete/restore comment (or no?)

---

## 8. Comment Event Tests

### ✅ Positive Cases
- `test_comment_event_created_on_federated` - comment.created event fired on federated comment
- `test_comment_event_includes_actor` - Event includes commenter_user_id as actor
- `test_comment_event_includes_thing_ids` - Event includes both comment_id and parent_id
- `test_comment_event_triggers_notification` - comment.created event triggers notification to post owner
- `test_comment_event_subscriptions_matched` - Event matches subscriptions correctly

### ❌ Negative Cases
- `test_comment_event_not_fired_on_failure` - Event not emitted if creation fails

---

## 9. Visibility & Access Control Tests

### ✅ Positive Cases
- `test_comment_inherits_public_post_visibility` - Comment on public post is public
- `test_comment_inherits_friends_post_visibility` - Comment on friends post is friends
- `test_comment_inherits_private_post_visibility` - Comment on private post is private
- `test_comment_access_by_post_owner` - Post owner always sees comments
- `test_comment_access_by_commenter` - Comment author always sees own comment
- `test_comment_access_by_friend` - Friend sees comment on friend-visible post
- `test_comment_access_by_stranger` - Stranger only sees public comments

### ❌ Negative Cases
- `test_comment_blocks_private_post_commenting` - Can't comment on private post (if enforced)
- `test_comment_unauthorized_access_denied` - Non-owner can't access private comments

---

## 10. Data Integrity & Consistency Tests

### ✅ Positive Cases
- `test_comment_data_persists` - Comment data survives restart
- `test_comment_metadata_json_valid` - Metadata is valid JSON
- `test_comment_timestamps_accurate` - created_at and updated_at are correct
- `test_comment_version_tracking` - Comment version increments on update

### ❌ Negative Cases
- `test_comment_concurrent_creation_no_race_condition` - 100 concurrent comments with unique IDs
- `test_comment_corrupted_metadata_handling` - Invalid JSON metadata doesn't crash

### ⚠️ Edge Cases
- `test_comment_timezone_handling` - Timestamps stored/returned in UTC correctly
- `test_comment_very_old_timestamp` - Can create comment with old created_at date (or reject?)

---

## 11. Federation Security Tests

### ✅ Positive Cases
- `test_comment_federation_endpoint_validation_https_required` - https:// endpoints accepted
- `test_comment_federation_endpoint_validation_http_allowed` - http:// endpoints accepted (dev)
- `test_comment_federation_prevents_self_comment` - Can't comment via own endpoint (if enforced)

### ❌ Negative Cases
- `test_comment_federation_blocks_http_in_production` - http:// rejected in prod (if enforced)
- `test_comment_federation_blocks_localhost` - localhost endpoints rejected (if enforced)
- `test_comment_federation_blocks_private_ips` - 192.168.*, 10.*, 172.16.* rejected (if enforced)
- `test_comment_federation_blocks_file_urls` - file://, data:// rejected
- `test_comment_federation_blocks_javascript_urls` - javascript: rejected

### 🔒 Security Cases
- `test_comment_federation_token_not_reusable` - Token can't be used twice (if implemented)
- `test_comment_federation_prevents_csrf` - CSRF protection on comment creation
- `test_comment_federation_prevents_xss` - Content properly escaped/sanitized
- `test_comment_federation_sql_injection_prevention` - SQL injection in content prevented
- `test_comment_federation_dos_prevention` - Rate limiting on comment creation

---

## 12. Media in Comments Tests (Future)

### ✅ Positive Cases
- `test_comment_with_media_url` - Comment can include media URL in content/metadata
- `test_comment_media_url_preserved` - Media URL stored exactly as provided
- `test_comment_multiple_media_urls` - Multiple URLs in one comment

### ❌ Negative Cases
- `test_comment_with_broken_media_url` - Broken URL stored as-is (no validation)
- `test_comment_media_url_to_deleted_instance` - URL breaks when media deleted

---

## 13. Tombstoning & Disappear Tests (Future)

### ✅ Positive Cases
- `test_tombstone_deleted_comment_shows_deleted_marker` - Content replaced with [deleted]
- `test_tombstone_preserves_thread_structure` - Replies to deleted comment still visible
- `test_tombstone_cached_instances_can_show_original` - Cached version available on request
- `test_disappear_user_deletes_all_comments` - Account deletion tombstones all comments
- `test_disappear_comments_remain_in_threads` - Tombstoned comments still occupy space in thread

### ❌ Negative Cases
- `test_tombstone_cannot_restore_from_api` - Deleted comments stay deleted

---

## Summary Statistics

| Category | Count | Status |
|----------|-------|--------|
| Positive Cases | ~50 | ❌ Not Written |
| Negative Cases | ~60 | ❌ Not Written |
| Edge Cases | ~40 | ❌ Not Written |
| Security Cases | ~20 | ❌ Not Written |
| **TOTAL** | **~170** | **❌ NEEDED** |

## Priority Testing Tiers

### Tier 1 (Critical - Must Have)
- Token creation/verification (core federation)
- Federated comment creation flow
- Depth validation
- Deletion & tombstoning
- Event emission

### Tier 2 (High - Should Have)
- Input validation (all endpoints)
- Visibility/access control
- Concurrent operations
- Error handling

### Tier 3 (Medium - Nice to Have)
- Unicode/encoding edge cases
- Performance (1000+ comments)
- Timestamp edge cases
- Federation security hardening

### Tier 4 (Low - Future Work)
- Media handling tests
- Full "disappear" account deletion
- Advanced caching scenarios
