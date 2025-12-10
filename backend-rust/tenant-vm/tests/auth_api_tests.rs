use actix_web::{test, web, App};
use serde_json::json;
use std::sync::Arc;

use tenant_vm::api::{self, AppState};
use tenant_vm::auth::AuthService;
use tenant_vm::events::EventProcessor;
use tenant_vm::store::Store;

/// Helper to create AppState with all required components
fn create_app_state(store: Arc<Store>, auth_service: Arc<AuthService>) -> AppState {
    AppState {
        store: store.clone(),
        auth_service: auth_service.clone(),
        event_processor: Arc::new(EventProcessor::new(store)),
    }
}

// ==================== Registration Tests ====================

#[actix_web::test]
async fn test_register_success() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "securepassword123"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // New Go-compatible format: { user, token }
    assert!(resp["token"].is_string());
    assert_eq!(resp["user"]["username"], "testuser");
    assert_eq!(resp["user"]["email"], "test@example.com");
    // First user should be admin
    assert_eq!(resp["user"]["is_admin"], true);
    // Password should not be in response
    assert!(resp["user"]["password"].is_null());
    assert!(resp["user"]["password_hash"].is_null());
}

#[actix_web::test]
async fn test_register_single_tenant_enforcement() {
    // Tests that registration is disabled after first user (Go parity)
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Register first user
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "testuser",
            "email": "test1@example.com",
            "password": "password123"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Try to register second user - should fail with 403 (single-tenant)
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "anotheruser",
            "email": "test2@example.com",
            "password": "password456"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403, "Should reject registration in single-tenant mode");
}

#[actix_web::test]
async fn test_register_username_length_validation() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Username too short (less than 3 chars)
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "ab",
            "email": "test@example.com",
            "password": "password123"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400, "Should reject username less than 3 chars");
}

#[actix_web::test]
async fn test_register_missing_fields_fails() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Missing password
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "testuser",
            "email": "test@example.com"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);

    // Missing username
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "email": "test@example.com",
            "password": "password123"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

// ==================== Login Tests ====================

#[actix_web::test]
async fn test_login_success() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // First register
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "mypassword123"
        }))
        .to_request();

    test::call_service(&app, req).await;

    // Now login with username
    let req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(json!({
            "username": "testuser",
            "password": "mypassword123"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // New Go-compatible format: { user, token }
    assert!(resp["token"].is_string());
    assert_eq!(resp["user"]["username"], "testuser");
}

#[actix_web::test]
async fn test_login_with_email() {
    // Tests that login works with email address (Go parity)
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // First register
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "mypassword123"
        }))
        .to_request();

    test::call_service(&app, req).await;

    // Login with email instead of username
    let req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(json!({
            "username": "test@example.com",
            "password": "mypassword123"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert!(resp["token"].is_string(), "Should be able to login with email");
    assert_eq!(resp["user"]["username"], "testuser");
}

#[actix_web::test]
async fn test_login_wrong_password_fails() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // First register
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "correctpassword"
        }))
        .to_request();

    test::call_service(&app, req).await;

    // Try login with wrong password
    let req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(json!({
            "username": "testuser",
            "password": "wrongpassword"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401, "Should reject wrong password");
}

#[actix_web::test]
async fn test_login_nonexistent_user_fails() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let req = test::TestRequest::post()
        .uri("/api/auth/login")
        .set_json(json!({
            "username": "doesnotexist",
            "password": "somepassword"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401, "Should reject nonexistent user");
}

// ==================== Get Current User Tests ====================

#[actix_web::test]
async fn test_get_current_user_success() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Register and get token
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let token = resp["token"].as_str().unwrap();

    // Get current user - returns user directly (Go format)
    let req = test::TestRequest::get()
        .uri("/api/auth/me")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["username"], "testuser");
    assert_eq!(resp["email"], "test@example.com");
}

#[actix_web::test]
async fn test_get_current_user_without_auth_fails() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let req = test::TestRequest::get()
        .uri("/api/auth/me")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_get_current_user_invalid_token_fails() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let req = test::TestRequest::get()
        .uri("/api/auth/me")
        .insert_header(("Authorization", "Bearer invalid_token_here"))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

// ==================== Auth Status Tests ====================

#[actix_web::test]
async fn test_auth_status_no_owner() {
    // Tests that auth status shows registration enabled when no users exist
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let req = test::TestRequest::get()
        .uri("/api/auth/status")
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // No users yet - registration should be enabled
    assert_eq!(resp["hasOwner"], false);
    assert_eq!(resp["registrationEnabled"], true);
    assert_eq!(resp["sandboxMode"], false);
    assert_eq!(resp["authDisabled"], false);
}

#[actix_web::test]
async fn test_auth_status_with_owner() {
    // Tests that auth status shows registration disabled after user exists
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Register a user
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "owner",
            "email": "owner@example.com",
            "password": "password123"
        }))
        .to_request();
    test::call_service(&app, req).await;

    // Now check status
    let req = test::TestRequest::get()
        .uri("/api/auth/status")
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // User exists - registration should be disabled
    assert_eq!(resp["hasOwner"], true);
    assert_eq!(resp["registrationEnabled"], false);
}

// ==================== Logout Tests ====================

#[actix_web::test]
async fn test_logout() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Register and get token
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let token = resp["token"].as_str().unwrap();

    // Logout - returns { status: "ok" } (Go format)
    let req = test::TestRequest::post()
        .uri("/api/auth/logout")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["status"], "ok");
}

// ==================== Token Persistence Tests ====================

#[actix_web::test]
async fn test_token_works_for_multiple_requests() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Register and get token
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let token = resp["token"].as_str().unwrap();

    // Make multiple requests with same token
    for _ in 0..3 {
        let req = test::TestRequest::get()
            .uri("/api/auth/me")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(resp["username"], "testuser");
    }
}

// ==================== Check Auth Tests ====================

#[actix_web::test]
async fn test_check_auth_with_valid_token() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Register and get token
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let token = resp["token"].as_str().unwrap();

    // Check auth with valid token
    let req = test::TestRequest::get()
        .uri("/api/auth/check")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["authenticated"], true);
    assert_eq!(resp["user"]["username"], "testuser");
}

#[actix_web::test]
async fn test_check_auth_without_token() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Check auth without token - should return authenticated: false
    let req = test::TestRequest::get()
        .uri("/api/auth/check")
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["authenticated"], false);
}

#[actix_web::test]
async fn test_check_auth_with_invalid_token() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Check auth with invalid token - should return authenticated: false
    let req = test::TestRequest::get()
        .uri("/api/auth/check")
        .insert_header(("Authorization", "Bearer invalid_token_here"))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["authenticated"], false);
}

#[actix_web::test]
async fn test_check_auth_locked_user() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Register and get token
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let token = resp["token"].as_str().unwrap();
    let user_id = resp["user"]["id"].as_str().unwrap();

    // Lock the user directly in the store
    store.lock_user(user_id).unwrap();

    // Check auth - should return authenticated: false for locked user
    let req = test::TestRequest::get()
        .uri("/api/auth/check")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["authenticated"], false);
}

// ==================== Update Profile Tests ====================

#[actix_web::test]
async fn test_update_current_user() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Register and get token
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let token = resp["token"].as_str().unwrap();

    // Update profile
    let req = test::TestRequest::put()
        .uri("/api/auth/me")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "displayName": "New Display Name",
            "bio": "This is my bio",
            "avatarUrl": "https://example.com/avatar.jpg"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["display_name"], "New Display Name");
    assert_eq!(resp["bio"], "This is my bio");
    assert_eq!(resp["avatar_url"], "https://example.com/avatar.jpg");
}

#[actix_web::test]
async fn test_update_current_user_partial() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Register with display name
    let req = test::TestRequest::post()
        .uri("/api/auth/register")
        .set_json(json!({
            "username": "testuser",
            "email": "test@example.com",
            "password": "password123",
            "displayName": "Original Name"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let token = resp["token"].as_str().unwrap();

    // Only update bio, not display name
    let req = test::TestRequest::put()
        .uri("/api/auth/me")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "bio": "Just a bio update"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Bio should be updated
    assert_eq!(resp["bio"], "Just a bio update");
    // Display name should remain unchanged (uses username since display_name wasn't in original register)
    assert_eq!(resp["display_name"], "testuser");
}

#[actix_web::test]
async fn test_update_current_user_without_auth() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Try to update without auth
    let req = test::TestRequest::put()
        .uri("/api/auth/me")
        .set_json(json!({
            "displayName": "Hacker"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}
