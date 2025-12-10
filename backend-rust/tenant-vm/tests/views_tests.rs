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

#[actix_web::test]
async fn test_list_views_empty() {
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

    let req = test::TestRequest::get()
        .uri("/api/views")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert!(resp.is_array());
    assert_eq!(resp.as_array().unwrap().len(), 0);
}

#[actix_web::test]
async fn test_create_view() {
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
        .uri("/api/views")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "My Feed",
            "type": "feed"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["name"], "My Feed");
    assert_eq!(resp["type"], "feed");
    assert!(resp["id"].is_string());
}

#[actix_web::test]
async fn test_create_view_default_type() {
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

    // Create view without type (should default to "feed")
    let req = test::TestRequest::post()
        .uri("/api/views")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Default View"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["type"], "feed");
}

#[actix_web::test]
async fn test_create_view_invalid_type() {
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
        .uri("/api/views")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Invalid View",
            "type": "invalid"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_create_view_empty_name() {
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
        .uri("/api/views")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": ""
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_get_view() {
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

    // Create a view
    let req = test::TestRequest::post()
        .uri("/api/views")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Test View",
            "type": "table"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let view_id = resp["id"].as_str().unwrap();

    // Get the view
    let req = test::TestRequest::get()
        .uri(&format!("/api/views/{}", view_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["name"], "Test View");
    assert_eq!(resp["type"], "table");
}

#[actix_web::test]
async fn test_get_view_not_found() {
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

    let req = test::TestRequest::get()
        .uri("/api/views/nonexistent-id")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn test_update_view() {
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

    // Create a view
    let req = test::TestRequest::post()
        .uri("/api/views")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Original Name",
            "type": "feed"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let view_id = resp["id"].as_str().unwrap();

    // Update the view
    let req = test::TestRequest::put()
        .uri(&format!("/api/views/{}", view_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Updated Name",
            "type": "board"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["name"], "Updated Name");
    assert_eq!(resp["type"], "board");
}

#[actix_web::test]
async fn test_delete_view() {
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

    // Create a view
    let req = test::TestRequest::post()
        .uri("/api/views")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "To Delete",
            "type": "feed"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let view_id = resp["id"].as_str().unwrap();

    // Delete the view
    let req = test::TestRequest::delete()
        .uri(&format!("/api/views/{}", view_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 204);

    // Verify it's gone
    let req = test::TestRequest::get()
        .uri(&format!("/api/views/{}", view_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn test_views_without_auth() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // List without auth
    let req = test::TestRequest::get()
        .uri("/api/views")
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);

    // Create without auth
    let req = test::TestRequest::post()
        .uri("/api/views")
        .set_json(json!({"name": "Test"}))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}
