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

// ==================== Create Kind Tests ====================

#[actix_web::test]
async fn test_create_kind() {
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
        .uri("/api/kinds")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Recipe",
            "icon": "🍳",
            "template": "A cooking recipe with ingredients and steps",
            "attributes": [
                {
                    "name": "ingredients",
                    "type": "text",
                    "required": true,
                    "options": ""
                },
                {
                    "name": "cook_time",
                    "type": "number",
                    "required": false,
                    "options": ""
                }
            ]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // API returns plain Kind object
    assert_eq!(resp["name"], "Recipe");
    assert_eq!(resp["icon"], "🍳");
    assert!(resp["id"].is_string());
    let attrs = resp["attributes"].as_array().unwrap();
    assert_eq!(attrs.len(), 2);
}

#[actix_web::test]
async fn test_create_kind_without_auth_fails() {
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
        .uri("/api/kinds")
        .set_json(json!({
            "name": "Test Kind",
            "icon": "📝",
            "template": "test template",
            "attributes": []
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_create_kind_minimal() {
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

    // Create kind with minimal fields (no attributes)
    let req = test::TestRequest::post()
        .uri("/api/kinds")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Simple",
            "icon": "📌",
            "template": ""
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["name"], "Simple");
    assert_eq!(resp["icon"], "📌");
}

// ==================== List Kinds Tests ====================

#[actix_web::test]
async fn test_list_kinds_empty() {
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
        .uri("/api/kinds")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    let kinds = resp.as_array().unwrap();
    assert_eq!(kinds.len(), 0);
}

#[actix_web::test]
async fn test_list_kinds() {
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

    // Create multiple kinds
    for i in 0..3 {
        let req = test::TestRequest::post()
            .uri("/api/kinds")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "name": format!("Kind {}", i),
                "icon": "📝",
                "template": format!("Template {}", i)
            }))
            .to_request();
        test::call_service(&app, req).await;
    }

    // List all kinds
    let req = test::TestRequest::get()
        .uri("/api/kinds")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    let kinds = resp.as_array().unwrap();
    assert_eq!(kinds.len(), 3);
}

// ==================== Get Kind Tests ====================

#[actix_web::test]
async fn test_get_kind_by_id() {
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

    // Create a kind
    let req = test::TestRequest::post()
        .uri("/api/kinds")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Bookmark",
            "icon": "🔖",
            "template": "Save a link"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let kind_id = resp["id"].as_str().unwrap();

    // Get by ID
    let req = test::TestRequest::get()
        .uri(&format!("/api/kinds/{}", kind_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["id"], kind_id);
    assert_eq!(resp["name"], "Bookmark");
}

#[actix_web::test]
async fn test_get_nonexistent_kind_fails() {
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
        .uri("/api/kinds/nonexistent-id")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

// ==================== Update Kind Tests ====================

#[actix_web::test]
async fn test_update_kind_name() {
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

    // Create a kind
    let req = test::TestRequest::post()
        .uri("/api/kinds")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Original Name",
            "icon": "📝",
            "template": "template"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let kind_id = resp["id"].as_str().unwrap();

    // Update the name
    let req = test::TestRequest::put()
        .uri(&format!("/api/kinds/{}", kind_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Updated Name"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["name"], "Updated Name");
    // Icon should remain unchanged
    assert_eq!(resp["icon"], "📝");
}

#[actix_web::test]
async fn test_update_kind_attributes() {
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

    // Create a kind without attributes
    let req = test::TestRequest::post()
        .uri("/api/kinds")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Expandable",
            "icon": "📝",
            "template": "template"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let kind_id = resp["id"].as_str().unwrap();

    // Add attributes
    let req = test::TestRequest::put()
        .uri(&format!("/api/kinds/{}", kind_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "attributes": [
                {
                    "name": "rating",
                    "type": "number",
                    "required": true,
                    "options": ""
                }
            ]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    let attrs = resp["attributes"].as_array().unwrap();
    assert_eq!(attrs.len(), 1);
    assert_eq!(attrs[0]["name"], "rating");
}

// ==================== Delete Kind Tests ====================

#[actix_web::test]
async fn test_delete_kind() {
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

    // Create a kind
    let req = test::TestRequest::post()
        .uri("/api/kinds")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "To Delete",
            "icon": "🗑️",
            "template": "template"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let kind_id = resp["id"].as_str().unwrap();

    // Delete the kind
    let req = test::TestRequest::delete()
        .uri(&format!("/api/kinds/{}", kind_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Verify it's gone
    let req = test::TestRequest::get()
        .uri(&format!("/api/kinds/{}", kind_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn test_delete_nonexistent_kind() {
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
        .uri("/api/kinds/nonexistent-id")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}
