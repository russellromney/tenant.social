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

/// Helper macro to register a user and get their token
macro_rules! register_and_get_token {
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
        resp["token"].as_str().unwrap().to_string()
    }};
}

// ==================== Public Profile Tests ====================
// Note: Public profile returns the first admin user's profile.
// Regular users registered via API are not admins, so these tests
// verify the expected behavior when no admin exists.

#[actix_web::test]
async fn test_get_public_profile_no_owner_returns_error() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Try to get public profile when no admin/owner exists
    let req = test::TestRequest::get()
        .uri("/api/public/profile")
        .to_request();

    let resp = test::call_service(&app, req).await;
    // Should return error since no admin exists
    // (Regular registered users are not admins)
    assert!(resp.status().is_server_error() || resp.status().as_u16() == 404);
}

#[actix_web::test]
async fn test_get_public_profile_no_auth_required() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Create a user (not an admin, so public profile won't return them)
    let _token = register_and_get_token!(app, "user");

    // Access public profile without any authentication
    let req = test::TestRequest::get()
        .uri("/api/public/profile")
        .to_request();

    let resp = test::call_service(&app, req).await;
    // Should not require auth, but will return error since no admin exists
    // The key thing is it doesn't return 401 Unauthorized
    assert_ne!(resp.status().as_u16(), 401, "Public profile should not require authentication");
}

// ==================== Public Things Tests ====================

#[actix_web::test]
async fn test_get_public_things_empty() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Get public things without creating any
    let req = test::TestRequest::get()
        .uri("/api/public/things")
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Should return empty array
    let things = resp.as_array().unwrap();
    assert_eq!(things.len(), 0);
}

#[actix_web::test]
async fn test_get_public_things_no_auth_required() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Access public things without any authentication
    let req = test::TestRequest::get()
        .uri("/api/public/things")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

#[actix_web::test]
async fn test_public_things_only_shows_public_visibility() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let token = register_and_get_token!(app, "testuser");

    // Create private thing
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "Private note",
            "visibility": "private"
        }))
        .to_request();
    test::call_service(&app, req).await;

    // Create friends-only thing
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "Friends note",
            "visibility": "friends"
        }))
        .to_request();
    test::call_service(&app, req).await;

    // Create public thing
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "Public note",
            "visibility": "public"
        }))
        .to_request();
    test::call_service(&app, req).await;

    // Get public things - should only return the public one
    let req = test::TestRequest::get()
        .uri("/api/public/things")
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    let things = resp.as_array().unwrap();
    assert_eq!(things.len(), 1, "Should only return public things");
    assert_eq!(things[0]["content"], "Public note");
    assert_eq!(things[0]["visibility"], "public");
}

#[actix_web::test]
async fn test_public_things_pagination() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let token = register_and_get_token!(app, "testuser");

    // Create 10 public things
    for i in 0..10 {
        let req = test::TestRequest::post()
            .uri("/api/things")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "type": "note",
                "content": format!("Public note {}", i),
                "visibility": "public"
            }))
            .to_request();
        test::call_service(&app, req).await;
    }

    // Get first page
    let req = test::TestRequest::get()
        .uri("/api/public/things?limit=5")
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let things = resp.as_array().unwrap();
    assert_eq!(things.len(), 5);

    // Get second page
    let req = test::TestRequest::get()
        .uri("/api/public/things?limit=5&offset=5")
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let things = resp.as_array().unwrap();
    assert_eq!(things.len(), 5);
}

#[actix_web::test]
async fn test_public_things_excludes_deleted() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let token = register_and_get_token!(app, "testuser");

    // Create a public thing
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "Will be deleted",
            "visibility": "public"
        }))
        .to_request();
    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let thing_id = resp["id"].as_str().unwrap();

    // Create another public thing that won't be deleted
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "Will remain",
            "visibility": "public"
        }))
        .to_request();
    test::call_service(&app, req).await;

    // Delete the first thing
    let req = test::TestRequest::delete()
        .uri(&format!("/api/things/{}", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    test::call_service(&app, req).await;

    // Get public things - should exclude deleted one
    let req = test::TestRequest::get()
        .uri("/api/public/things")
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let things = resp.as_array().unwrap();

    assert_eq!(things.len(), 1, "Deleted thing should not appear in public things");
    assert_eq!(things[0]["content"], "Will remain");
}
