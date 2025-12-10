use actix_web::{test, web, App};
use serde_json::json;
use std::sync::Arc;

use tenant_vm::api::{self, AppState};
use tenant_vm::auth::AuthService;
use tenant_vm::events::EventProcessor;
use tenant_vm::store::Store;

fn create_app_state(store: Arc<Store>, auth_service: Arc<AuthService>) -> AppState {
    AppState {
        store: store.clone(),
        auth_service: auth_service.clone(),
        event_processor: Arc::new(EventProcessor::new(store)),
    }
}

/// Helper macro to register a user and get their token and user_id
macro_rules! register_and_get_token_id {
    ($app:expr, $username:expr) => {{
        let req = test::TestRequest::post()
            .uri("/api/auth/register")
            .set_json(json!({
                "username": $username,
                "email": format!("{}@example.com", $username),
                "password": "password123"
            }))
            .to_request();

        let resp: serde_json::Value = test::call_and_read_body_json(&$app, req).await;
        let token = resp["token"].as_str().unwrap().to_string();
        let user_id = resp["user"]["id"].as_str().unwrap().to_string();
        (token, user_id)
    }};
}

// Note: In single-tenant mode, only one user can register.
// These tests need special handling since we can't register multiple users.
// The first user is always admin, so they can perform admin operations.

#[actix_web::test]
async fn test_list_users() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Register first user (becomes admin)
    let (token, _) = register_and_get_token_id!(app, "admin");

    // List users
    let req = test::TestRequest::get()
        .uri("/api/admin/users")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Should return an array with one user
    assert!(resp.is_array());
    let users = resp.as_array().unwrap();
    assert_eq!(users.len(), 1);
    assert_eq!(users[0]["username"], "admin");
    // Password hash should not be exposed
    assert!(users[0]["password_hash"].is_null());
}

#[actix_web::test]
async fn test_list_users_without_auth() {
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
        .uri("/api/admin/users")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_lock_unlock_user() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Register admin user
    let (token, user_id) = register_and_get_token_id!(app, "admin");

    // Create another user directly in the store for testing
    let mut test_user = tenant_vm::models::User {
        id: String::new(),
        username: "testuser".to_string(),
        email: "test@example.com".to_string(),
        password_hash: "$2b$10$test".to_string(),
        display_name: "Test".to_string(),
        bio: String::new(),
        avatar_url: String::new(),
        is_admin: false,
        is_locked: false,
        recovery_hash: String::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store.create_user(&mut test_user).unwrap();

    // Lock the test user
    let req = test::TestRequest::put()
        .uri(&format!("/api/admin/users/{}/lock", test_user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["status"], "ok");

    // Verify user is locked
    let locked_user = store.get_user(&test_user.id).unwrap();
    assert!(locked_user.is_locked);

    // Unlock the user
    let req = test::TestRequest::put()
        .uri(&format!("/api/admin/users/{}/unlock", test_user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["status"], "ok");

    // Verify user is unlocked
    let unlocked_user = store.get_user(&test_user.id).unwrap();
    assert!(!unlocked_user.is_locked);
}

#[actix_web::test]
async fn test_cannot_lock_self() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let (token, user_id) = register_and_get_token_id!(app, "admin");

    // Try to lock yourself
    let req = test::TestRequest::put()
        .uri(&format!("/api/admin/users/{}/lock", user_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_delete_user() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let (token, _) = register_and_get_token_id!(app, "admin");

    // Create another user directly in the store
    let mut test_user = tenant_vm::models::User {
        id: String::new(),
        username: "todelete".to_string(),
        email: "delete@example.com".to_string(),
        password_hash: "$2b$10$test".to_string(),
        display_name: "To Delete".to_string(),
        bio: String::new(),
        avatar_url: String::new(),
        is_admin: false,
        is_locked: false,
        recovery_hash: String::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store.create_user(&mut test_user).unwrap();

    // Delete the user
    let req = test::TestRequest::delete()
        .uri(&format!("/api/admin/users/{}", test_user.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["status"], "ok");

    // Verify user is gone
    assert!(store.get_user(&test_user.id).is_err());
}

#[actix_web::test]
async fn test_cannot_delete_self() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let (token, user_id) = register_and_get_token_id!(app, "admin");

    // Try to delete yourself
    let req = test::TestRequest::delete()
        .uri(&format!("/api/admin/users/{}", user_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_lock_nonexistent_user() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let (token, _) = register_and_get_token_id!(app, "admin");

    let req = test::TestRequest::put()
        .uri("/api/admin/users/nonexistent-id/lock")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}
