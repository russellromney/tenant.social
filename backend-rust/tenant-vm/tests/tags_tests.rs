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
async fn test_list_tags_empty() {
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

    // List tags (should be empty)
    let req = test::TestRequest::get()
        .uri("/api/tags")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert!(resp.is_array());
    assert_eq!(resp.as_array().unwrap().len(), 0);
}

#[actix_web::test]
async fn test_create_tag() {
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

    // Create a tag
    let req = test::TestRequest::post()
        .uri("/api/tags")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "important"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["name"], "important");
    assert!(resp["id"].is_string());
}

#[actix_web::test]
async fn test_create_tag_empty_name() {
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

    // Create a tag with empty name
    let req = test::TestRequest::post()
        .uri("/api/tags")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": ""
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_create_duplicate_tag_returns_existing() {
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

    // Create first tag
    let req = test::TestRequest::post()
        .uri("/api/tags")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "work"
        }))
        .to_request();

    let resp1: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let first_id = resp1["id"].as_str().unwrap();

    // Create tag with same name
    let req = test::TestRequest::post()
        .uri("/api/tags")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "work"
        }))
        .to_request();

    let resp2: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Should return the same tag
    assert_eq!(resp2["id"].as_str().unwrap(), first_id);
    assert_eq!(resp2["name"], "work");
}

#[actix_web::test]
async fn test_list_tags_with_tags() {
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

    // Create some tags
    for name in ["alpha", "beta", "gamma"] {
        let req = test::TestRequest::post()
            .uri("/api/tags")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "name": name
            }))
            .to_request();
        test::call_service(&app, req).await;
    }

    // List tags
    let req = test::TestRequest::get()
        .uri("/api/tags")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    let tags = resp.as_array().unwrap();
    assert_eq!(tags.len(), 3);
    // Tags should be ordered by name
    assert_eq!(tags[0]["name"], "alpha");
    assert_eq!(tags[1]["name"], "beta");
    assert_eq!(tags[2]["name"], "gamma");
}

#[actix_web::test]
async fn test_list_tags_without_auth() {
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
        .uri("/api/tags")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_create_tag_without_auth() {
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
        .uri("/api/tags")
        .set_json(json!({
            "name": "test"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}
