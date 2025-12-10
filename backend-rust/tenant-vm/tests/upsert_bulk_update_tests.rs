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

// ==================== Upsert Tests ====================

#[actix_web::test]
async fn test_upsert_creates_new_thing() {
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

    // Upsert a new thing with a unique field
    let req = test::TestRequest::put()
        .uri("/api/things/upsert?type=bookmark&matchField=url&matchValue=https://example.com")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "content": "Example Website",
            "metadata": {
                "url": "https://example.com",
                "title": "Example"
            }
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201); // Created

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["created"], true);
    assert!(body["thing"]["id"].is_string());
    assert_eq!(body["thing"]["content"], "Example Website");
}

#[actix_web::test]
async fn test_upsert_updates_existing_thing() {
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

    // First upsert - creates
    let req = test::TestRequest::put()
        .uri("/api/things/upsert?type=bookmark&matchField=url&matchValue=https://example.com")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "content": "Original Content",
            "metadata": {
                "url": "https://example.com"
            }
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["created"], true);
    let original_id = resp["thing"]["id"].as_str().unwrap().to_string();

    // Second upsert with same match - updates
    let req = test::TestRequest::put()
        .uri("/api/things/upsert?type=bookmark&matchField=url&matchValue=https://example.com")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "content": "Updated Content",
            "metadata": {
                "url": "https://example.com",
                "newField": "added"
            }
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 200); // OK (updated, not created)

    let body: serde_json::Value = test::read_body_json(resp).await;
    assert_eq!(body["created"], false);
    assert_eq!(body["thing"]["id"], original_id); // Same ID
    assert_eq!(body["thing"]["content"], "Updated Content");
}

#[actix_web::test]
async fn test_upsert_missing_type() {
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

    let req = test::TestRequest::put()
        .uri("/api/things/upsert?matchField=url&matchValue=https://example.com")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({"content": "Test"}))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_upsert_missing_match_field() {
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

    let req = test::TestRequest::put()
        .uri("/api/things/upsert?type=bookmark&matchValue=https://example.com")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({"content": "Test"}))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_upsert_missing_match_value() {
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

    let req = test::TestRequest::put()
        .uri("/api/things/upsert?type=bookmark&matchField=url")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({"content": "Test"}))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_upsert_without_auth() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let req = test::TestRequest::put()
        .uri("/api/things/upsert?type=bookmark&matchField=url&matchValue=test")
        .set_json(json!({"content": "Test"}))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

// ==================== Bulk Update Tests ====================

#[actix_web::test]
async fn test_bulk_update_things() {
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
    let id1 = create_thing!(app, &token, "note", "Note 1");
    let id2 = create_thing!(app, &token, "note", "Note 2");

    // Bulk update both things
    let req = test::TestRequest::put()
        .uri("/api/things/bulk")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "things": [
                {"id": id1, "type": "note", "content": "Updated Note 1"},
                {"id": id2, "type": "note", "content": "Updated Note 2"}
            ]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["updated"], 2);
    assert!(resp["things"].is_array());
    assert_eq!(resp["things"].as_array().unwrap().len(), 2);
}

#[actix_web::test]
async fn test_bulk_update_empty() {
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

    let req = test::TestRequest::put()
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
async fn test_bulk_update_missing_id() {
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

    let req = test::TestRequest::put()
        .uri("/api/things/bulk")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "things": [
                {"type": "note", "content": "Missing ID"}
            ]
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_bulk_update_without_auth() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let req = test::TestRequest::put()
        .uri("/api/things/bulk")
        .set_json(json!({
            "things": [{"id": "some-id", "content": "Test"}]
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_bulk_update_nonexistent() {
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

    // Try to update nonexistent things
    let req = test::TestRequest::put()
        .uri("/api/things/bulk")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "things": [
                {"id": "nonexistent-1", "type": "note", "content": "Won't update"},
                {"id": "nonexistent-2", "type": "note", "content": "Won't update either"}
            ]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    // Should return 0 updated (no error, just nothing found)
    assert_eq!(resp["updated"], 0);
}

#[actix_web::test]
async fn test_bulk_update_increments_version() {
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

    // Create a thing
    let id = create_thing!(app, &token, "note", "Original content");

    // Get original version
    let req = test::TestRequest::get()
        .uri(&format!("/api/things/{}", id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let original: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let original_version = original["version"].as_i64().unwrap();

    // Bulk update
    let req = test::TestRequest::put()
        .uri("/api/things/bulk")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "things": [
                {"id": id, "type": "note", "content": "Updated content", "version": original_version}
            ]
        }))
        .to_request();
    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["updated"], 1);

    // Verify version was incremented
    let req = test::TestRequest::get()
        .uri(&format!("/api/things/{}", id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let updated: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(updated["version"].as_i64().unwrap(), original_version + 1);
}
