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

// ==================== Bulk Create Tests ====================

#[actix_web::test]
async fn test_bulk_create_things() {
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

    // Bulk create 3 things
    let req = test::TestRequest::post()
        .uri("/api/things/bulk")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "things": [
                {"type": "note", "content": "Note 1", "visibility": "private"},
                {"type": "note", "content": "Note 2", "visibility": "public"},
                {"type": "task", "content": "Task 1", "visibility": "private"}
            ]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["created"], 3);
    assert!(resp["things"].is_array());
    assert_eq!(resp["things"].as_array().unwrap().len(), 3);
}

#[actix_web::test]
async fn test_bulk_create_empty() {
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

    let req = test::TestRequest::post()
        .uri("/api/things/bulk")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "things": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_bulk_create_without_auth() {
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
        .uri("/api/things/bulk")
        .set_json(json!({
            "things": [{"type": "note", "content": "Test"}]
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

// ==================== Bulk Delete Tests ====================

#[actix_web::test]
async fn test_bulk_delete_things() {
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

    // Create some things first
    let req = test::TestRequest::post()
        .uri("/api/things/bulk")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "things": [
                {"type": "note", "content": "Note 1"},
                {"type": "note", "content": "Note 2"},
                {"type": "note", "content": "Note 3"}
            ]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let things = resp["things"].as_array().unwrap();
    let ids: Vec<&str> = things.iter().map(|t| t["id"].as_str().unwrap()).collect();

    // Bulk delete 2 of them
    let req = test::TestRequest::delete()
        .uri("/api/things/bulk")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "ids": [ids[0], ids[1]]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["deleted"], 2);
}

#[actix_web::test]
async fn test_bulk_delete_empty() {
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

    let req = test::TestRequest::delete()
        .uri("/api/things/bulk")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "ids": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_bulk_delete_without_auth() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let req = test::TestRequest::delete()
        .uri("/api/things/bulk")
        .set_json(json!({
            "ids": ["some-id"]
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_bulk_delete_nonexistent() {
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

    // Try to delete nonexistent things
    let req = test::TestRequest::delete()
        .uri("/api/things/bulk")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "ids": ["nonexistent-1", "nonexistent-2"]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    // Should return 0 deleted (no error, just nothing found)
    assert_eq!(resp["deleted"], 0);
}
