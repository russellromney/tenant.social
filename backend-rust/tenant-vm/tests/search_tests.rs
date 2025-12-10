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

/// Helper macro to create a thing and return its ID
macro_rules! create_thing {
    ($app:expr, $token:expr, $thing_type:expr, $content:expr) => {{
        let req = test::TestRequest::post()
            .uri("/api/things")
            .insert_header(("Authorization", format!("Bearer {}", $token)))
            .set_json(json!({
                "type": $thing_type,
                "content": $content,
                "visibility": "private"
            }))
            .to_request();

        let resp: serde_json::Value = test::call_and_read_body_json(&$app, req).await;
        resp["id"].as_str().unwrap().to_string()
    }};
}

// ==================== Search Tests ====================

#[actix_web::test]
async fn test_search_things_empty() {
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
        .uri("/api/things/search?q=nothing")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert!(resp.is_array());
    assert_eq!(resp.as_array().unwrap().len(), 0);
}

#[actix_web::test]
async fn test_search_things_by_content() {
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

    // Create some things
    create_thing!(app, &token, "note", "Hello world");
    create_thing!(app, &token, "note", "Goodbye world");
    create_thing!(app, &token, "task", "Something else");

    // Search for "world"
    let req = test::TestRequest::get()
        .uri("/api/things/search?q=world")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert!(resp.is_array());
    assert_eq!(resp.as_array().unwrap().len(), 2);
}

#[actix_web::test]
async fn test_search_things_by_type() {
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

    // Create things of different types
    create_thing!(app, &token, "note", "A note");
    create_thing!(app, &token, "task", "A task");
    create_thing!(app, &token, "bookmark", "A bookmark");

    // Search for type "task"
    let req = test::TestRequest::get()
        .uri("/api/things/search?q=task")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert!(resp.is_array());
    assert!(resp.as_array().unwrap().len() >= 1);
}

#[actix_web::test]
async fn test_search_things_with_limit() {
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

    // Create several things
    for i in 1..=5 {
        create_thing!(app, &token, "note", format!("Test note {}", i));
    }

    // Search with limit
    let req = test::TestRequest::get()
        .uri("/api/things/search?q=Test&limit=2")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert!(resp.is_array());
    assert_eq!(resp.as_array().unwrap().len(), 2);
}

#[actix_web::test]
async fn test_search_things_without_auth() {
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
        .uri("/api/things/search?q=test")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

// ==================== Query Tests ====================

#[actix_web::test]
async fn test_query_things_basic() {
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

    // Create some things
    create_thing!(app, &token, "note", "Note 1");
    create_thing!(app, &token, "note", "Note 2");
    create_thing!(app, &token, "task", "Task 1");

    let req = test::TestRequest::get()
        .uri("/api/things/query")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["total"], 3);
    assert!(resp["things"].is_array());
    assert_eq!(resp["things"].as_array().unwrap().len(), 3);
}

#[actix_web::test]
async fn test_query_things_by_type() {
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

    // Create things of different types
    create_thing!(app, &token, "note", "Note 1");
    create_thing!(app, &token, "note", "Note 2");
    create_thing!(app, &token, "task", "Task 1");

    let req = test::TestRequest::get()
        .uri("/api/things/query?type=note")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["total"], 2);
    assert_eq!(resp["things"].as_array().unwrap().len(), 2);
}

#[actix_web::test]
async fn test_query_things_pagination() {
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

    // Create 5 things
    for i in 1..=5 {
        create_thing!(app, &token, "note", format!("Note {}", i));
    }

    // Query with count=2
    let req = test::TestRequest::get()
        .uri("/api/things/query?count=2&page=1")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["total"], 5);
    assert_eq!(resp["count"], 2);
    assert_eq!(resp["page"], 1);
    assert_eq!(resp["total_pages"], 3);
    assert_eq!(resp["things"].as_array().unwrap().len(), 2);
}

#[actix_web::test]
async fn test_query_things_sorting() {
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

    // Create things
    create_thing!(app, &token, "note", "A first");
    create_thing!(app, &token, "note", "B second");
    create_thing!(app, &token, "note", "C third");

    // Query with sort by content ascending
    let req = test::TestRequest::get()
        .uri("/api/things/query?sort=content")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let things = resp["things"].as_array().unwrap();
    assert_eq!(things[0]["content"], "A first");
    assert_eq!(things[1]["content"], "B second");
    assert_eq!(things[2]["content"], "C third");
}

#[actix_web::test]
async fn test_query_things_sort_descending() {
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

    // Create things
    create_thing!(app, &token, "note", "A first");
    create_thing!(app, &token, "note", "B second");
    create_thing!(app, &token, "note", "C third");

    // Query with sort by content descending (with - prefix)
    let req = test::TestRequest::get()
        .uri("/api/things/query?sort=-content")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let things = resp["things"].as_array().unwrap();
    assert_eq!(things[0]["content"], "C third");
    assert_eq!(things[1]["content"], "B second");
    assert_eq!(things[2]["content"], "A first");
}

#[actix_web::test]
async fn test_query_things_without_auth() {
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
        .uri("/api/things/query")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}
