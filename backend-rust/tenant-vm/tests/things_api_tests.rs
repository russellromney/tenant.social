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

// ==================== Create Thing Tests ====================

#[actix_web::test]
async fn test_create_note() {
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
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "My first note content",
            "visibility": "private"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // API returns plain Thing object (not wrapped in success/data)
    assert_eq!(resp["type"], "note");
    assert_eq!(resp["content"], "My first note content");
    assert_eq!(resp["visibility"], "private");
    assert!(resp["id"].is_string());
}

#[actix_web::test]
async fn test_create_link_with_metadata() {
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
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "link",
            "content": "Check out this article",
            "metadata": {
                "url": "https://example.com/article",
                "title": "Example Article"
            },
            "visibility": "public"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["type"], "link");
    assert_eq!(resp["metadata"]["url"], "https://example.com/article");
    assert_eq!(resp["visibility"], "public");
}

#[actix_web::test]
async fn test_create_task_with_done_status() {
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
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "task",
            "content": "Buy groceries",
            "metadata": {
                "done": false
            },
            "visibility": "private"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["type"], "task");
    assert_eq!(resp["content"], "Buy groceries");
    assert_eq!(resp["metadata"]["done"], false);
}

#[actix_web::test]
async fn test_create_thing_without_auth_fails() {
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
        .uri("/api/things")
        .set_json(json!({
            "type": "note",
            "content": "Test content",
            "visibility": "private"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

// ==================== List Things Tests ====================

#[actix_web::test]
async fn test_list_things() {
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

    // Create multiple things
    for i in 0..5 {
        let req = test::TestRequest::post()
            .uri("/api/things")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "type": "note",
                "content": format!("Note {}", i),
                "visibility": "private"
            }))
            .to_request();
        test::call_service(&app, req).await;
    }

    // List all things - API returns plain array
    let req = test::TestRequest::get()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Response is a plain array
    let things = resp.as_array().unwrap();
    assert_eq!(things.len(), 5);
}

#[actix_web::test]
async fn test_list_things_filter_by_type() {
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

    // Create notes
    for i in 0..3 {
        let req = test::TestRequest::post()
            .uri("/api/things")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "type": "note",
                "content": format!("Note {}", i),
                "visibility": "private"
            }))
            .to_request();
        test::call_service(&app, req).await;
    }

    // Create tasks
    for i in 0..2 {
        let req = test::TestRequest::post()
            .uri("/api/things")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "type": "task",
                "content": format!("Task {}", i),
                "visibility": "private"
            }))
            .to_request();
        test::call_service(&app, req).await;
    }

    // Filter by type=note
    let req = test::TestRequest::get()
        .uri("/api/things?type=note")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    let things = resp.as_array().unwrap();
    assert_eq!(things.len(), 3);
    for thing in things {
        assert_eq!(thing["type"], "note");
    }
}

#[actix_web::test]
async fn test_list_things_pagination() {
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

    // Create 10 things
    for i in 0..10 {
        let req = test::TestRequest::post()
            .uri("/api/things")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "type": "note",
                "content": format!("Note {}", i),
                "visibility": "private"
            }))
            .to_request();
        test::call_service(&app, req).await;
    }

    // Get first page (limit 5)
    let req = test::TestRequest::get()
        .uri("/api/things?limit=5")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let things = resp.as_array().unwrap();
    assert_eq!(things.len(), 5);

    // Get second page
    let req = test::TestRequest::get()
        .uri("/api/things?limit=5&offset=5")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let things = resp.as_array().unwrap();
    assert_eq!(things.len(), 5);
}

// ==================== Get Single Thing Tests ====================

#[actix_web::test]
async fn test_get_thing_by_id() {
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
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "My specific note",
            "visibility": "private"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let thing_id = resp["id"].as_str().unwrap();

    // Get by ID
    let req = test::TestRequest::get()
        .uri(&format!("/api/things/{}", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["id"], thing_id);
    assert_eq!(resp["content"], "My specific note");
}

#[actix_web::test]
async fn test_get_nonexistent_thing_fails() {
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
        .uri("/api/things/nonexistent-id-12345")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

// ==================== Update Thing Tests ====================

#[actix_web::test]
async fn test_update_thing_content() {
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
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "Original content",
            "visibility": "private"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let thing_id = resp["id"].as_str().unwrap();

    // Update the thing
    let req = test::TestRequest::put()
        .uri(&format!("/api/things/{}", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "content": "Updated content"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["content"], "Updated content");
}

#[actix_web::test]
async fn test_update_thing_visibility() {
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
            "content": "Test note",
            "visibility": "private"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let thing_id = resp["id"].as_str().unwrap();

    // Change to public
    let req = test::TestRequest::put()
        .uri(&format!("/api/things/{}", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "visibility": "public"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["visibility"], "public");
}

#[actix_web::test]
async fn test_update_task_mark_done() {
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

    // Create task
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "task",
            "content": "Buy milk",
            "metadata": { "done": false },
            "visibility": "private"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let thing_id = resp["id"].as_str().unwrap();

    // Mark as done
    let req = test::TestRequest::put()
        .uri(&format!("/api/things/{}", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "metadata": { "done": true }
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["metadata"]["done"], true);
}

// ==================== Delete Thing Tests ====================

#[actix_web::test]
async fn test_delete_thing() {
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
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "To be deleted",
            "visibility": "private"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let thing_id = resp["id"].as_str().unwrap();

    // Delete the thing (soft delete)
    let req = test::TestRequest::delete()
        .uri(&format!("/api/things/{}", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success(), "Delete should succeed");

    // Soft delete: Thing is still retrievable but has deleted_at set
    let req = test::TestRequest::get()
        .uri(&format!("/api/things/{}", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    // deleted_at should be set (not null)
    assert!(!resp["deleted_at"].is_null(), "Deleted thing should have deleted_at set");
}

#[actix_web::test]
async fn test_delete_nonexistent_thing() {
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
        .uri("/api/things/nonexistent-id")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // Should return 404 for nonexistent thing
    assert_eq!(resp.status(), 404);
}

// ==================== Visibility Tests ====================

#[actix_web::test]
async fn test_visibility_levels() {
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

    // Create things with different visibility
    let visibility_levels = vec!["private", "friends", "public"];

    for visibility in &visibility_levels {
        let req = test::TestRequest::post()
            .uri("/api/things")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "type": "note",
                "content": format!("{} note", visibility),
                "visibility": visibility
            }))
            .to_request();

        let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(resp["visibility"], *visibility);
    }
}

// ==================== Backlinks Tests ====================

#[actix_web::test]
async fn test_get_backlinks() {
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
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "Target note",
            "visibility": "private"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let thing_id = resp["id"].as_str().unwrap();

    // Get backlinks (endpoint should exist even if empty)
    let req = test::TestRequest::get()
        .uri(&format!("/api/things/{}/backlinks", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
}

// ==================== Restore Thing Tests ====================

#[actix_web::test]
async fn test_restore_deleted_thing() {
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
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "To be deleted and restored",
            "visibility": "private"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let thing_id = resp["id"].as_str().unwrap();

    // Delete the thing (soft delete)
    let req = test::TestRequest::delete()
        .uri(&format!("/api/things/{}", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Verify it's deleted
    let req = test::TestRequest::get()
        .uri(&format!("/api/things/{}", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert!(!resp["deleted_at"].is_null(), "Thing should have deleted_at set");

    // Restore the thing
    let req = test::TestRequest::post()
        .uri(&format!("/api/things/{}/restore", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Restored thing should have null deleted_at
    assert!(resp["deleted_at"].is_null(), "Restored thing should have null deleted_at");
    assert_eq!(resp["content"], "To be deleted and restored");
}

#[actix_web::test]
async fn test_restore_nonexistent_thing() {
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

    // Try to restore nonexistent thing
    let req = test::TestRequest::post()
        .uri("/api/things/nonexistent-id/restore")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn test_restore_thing_without_auth() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Try to restore without auth
    let req = test::TestRequest::post()
        .uri("/api/things/some-id/restore")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}
