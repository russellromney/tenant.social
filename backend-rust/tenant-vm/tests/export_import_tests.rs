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

// ==================== Export Tests ====================

#[actix_web::test]
async fn test_export_data_empty() {
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
        .uri("/api/export")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["version"], "1.0");
    assert!(resp["exportedAt"].is_string());
    assert!(resp["things"].is_array());
    assert!(resp["kinds"].is_array());
    assert_eq!(resp["things"].as_array().unwrap().len(), 0);
}

#[actix_web::test]
async fn test_export_data_with_things() {
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
    create_thing!(app, &token, "task", "Task 1");
    create_thing!(app, &token, "note", "Note 2");

    let req = test::TestRequest::get()
        .uri("/api/export")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["version"], "1.0");
    assert_eq!(resp["things"].as_array().unwrap().len(), 3);
}

#[actix_web::test]
async fn test_export_data_without_auth() {
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
        .uri("/api/export")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

// ==================== Import Tests ====================

#[actix_web::test]
async fn test_import_data_things() {
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

    let import_data = json!({
        "version": "1.0",
        "exportedAt": "2024-01-01T00:00:00Z",
        "things": [
            {"type": "note", "content": "Imported note 1"},
            {"type": "task", "content": "Imported task 1"},
            {"type": "note", "content": "Imported note 2"}
        ],
        "kinds": []
    });

    let req = test::TestRequest::post()
        .uri("/api/import")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(&import_data)
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["message"], "Import completed");
    assert_eq!(resp["thingsCreated"], 3);
    assert_eq!(resp["thingsSkipped"], 0);
}

#[actix_web::test]
async fn test_import_data_missing_version() {
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

    let import_data = json!({
        "things": [],
        "kinds": []
    });

    let req = test::TestRequest::post()
        .uri("/api/import")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(&import_data)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_import_data_without_auth() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let import_data = json!({
        "version": "1.0",
        "things": [],
        "kinds": []
    });

    let req = test::TestRequest::post()
        .uri("/api/import")
        .set_json(&import_data)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_export_import_roundtrip() {
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
    create_thing!(app, &token, "note", "Original note");
    create_thing!(app, &token, "task", "Original task");

    // Export data
    let req = test::TestRequest::get()
        .uri("/api/export")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let export_data: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(export_data["things"].as_array().unwrap().len(), 2);

    // Now create a fresh store for import test
    let store2 = Arc::new(Store::new(":memory:").unwrap());
    let auth_service2 = Arc::new(AuthService::new("test_secret".to_string(), store2.clone()));

    let app2 = test::init_service(
        App::new()
            .app_data(web::Data::new(store2.clone()))
            .app_data(web::Data::new(auth_service2.clone()))
            .app_data(web::Data::new(create_app_state(store2.clone(), auth_service2.clone())))
            .configure(api::configure_routes)
    ).await;

    let token2 = register_and_get_token!(app2, "testuser2");

    // Import the exported data
    let req = test::TestRequest::post()
        .uri("/api/import")
        .insert_header(("Authorization", format!("Bearer {}", token2)))
        .set_json(&export_data)
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app2, req).await;
    assert_eq!(resp["thingsCreated"], 2);

    // Verify things were imported
    let req = test::TestRequest::get()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token2)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app2, req).await;
    assert_eq!(resp.as_array().unwrap().len(), 2);
}

#[actix_web::test]
async fn test_import_kinds() {
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

    let import_data = json!({
        "version": "1.0",
        "exportedAt": "2024-01-01T00:00:00Z",
        "things": [],
        "kinds": [
            {"name": "Recipe", "icon": "cooking", "template": "", "attributes": []},
            {"name": "Bookmark", "icon": "link", "template": "", "attributes": []}
        ]
    });

    let req = test::TestRequest::post()
        .uri("/api/import")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(&import_data)
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["message"], "Import completed");
    assert_eq!(resp["kindsCreated"], 2);
    assert_eq!(resp["kindsSkipped"], 0);
}

#[actix_web::test]
async fn test_import_skips_duplicate_kinds() {
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

    // Import first batch
    let import_data = json!({
        "version": "1.0",
        "things": [],
        "kinds": [
            {"name": "Recipe", "icon": "cooking", "template": "", "attributes": []}
        ]
    });

    let req = test::TestRequest::post()
        .uri("/api/import")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(&import_data)
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["kindsCreated"], 1);

    // Import again with same kind - should be skipped
    let req = test::TestRequest::post()
        .uri("/api/import")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(&import_data)
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["kindsCreated"], 0);
    assert_eq!(resp["kindsSkipped"], 1);
}
