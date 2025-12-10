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

// ==================== Create API Key Tests ====================

#[actix_web::test]
async fn test_create_api_key() {
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
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "My API Key",
            "scopes": ["things:read", "things:write"]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Go-compatible format: direct object
    assert_eq!(resp["name"], "My API Key");
    // Key should be returned on creation
    assert!(resp["key"].is_string());
    // Scopes should be preserved
    let scopes = resp["scopes"].as_array().unwrap();
    assert!(scopes.contains(&json!("things:read")));
    assert!(scopes.contains(&json!("things:write")));
}

#[actix_web::test]
async fn test_create_api_key_without_auth_fails() {
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
        .uri("/api/keys")
        .set_json(json!({
            "name": "Test Key",
            "scopes": ["things:read"]
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_create_api_key_with_all_scopes() {
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

    // Create key with many scopes
    let req = test::TestRequest::post()
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Full Access Key",
            "scopes": [
                "things:read",
                "things:write",
                "things:delete",
                "kinds:read",
                "kinds:write",
                "keys:manage"
            ]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Go-compatible format
    let scopes = resp["scopes"].as_array().unwrap();
    assert_eq!(scopes.len(), 6);
}

// ==================== List API Keys Tests ====================

#[actix_web::test]
async fn test_list_api_keys_empty() {
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
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Go-compatible format: { keys: [...], availableScopes: [...] }
    let keys = resp["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 0);
    // Should include available scopes
    assert!(resp["availableScopes"].is_array());
}

#[actix_web::test]
async fn test_list_api_keys() {
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

    // Create multiple API keys
    for i in 0..3 {
        let req = test::TestRequest::post()
            .uri("/api/keys")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "name": format!("Key {}", i),
                "scopes": ["things:read"]
            }))
            .to_request();
        test::call_service(&app, req).await;
    }

    // List all keys
    let req = test::TestRequest::get()
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Go-compatible format
    let keys = resp["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 3);
}

#[actix_web::test]
async fn test_list_api_keys_hides_key_value() {
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

    // Create a key
    let req = test::TestRequest::post()
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Secret Key",
            "scopes": ["things:read"]
        }))
        .to_request();
    test::call_service(&app, req).await;

    // List keys - key value should not be exposed
    let req = test::TestRequest::get()
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    let keys = resp["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 1);
    // The full key should not be visible in list
    // (It should only be shown once during creation)
    // Check that either key is null or only shows a prefix
    let key_value = &keys[0]["key"];
    assert!(
        key_value.is_null() || key_value.as_str().map(|s| s.len() < 20).unwrap_or(true),
        "Full API key should not be exposed in list"
    );
}

// ==================== Delete API Key Tests ====================

#[actix_web::test]
async fn test_delete_api_key() {
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

    // Create a key
    let req = test::TestRequest::post()
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "To Delete",
            "scopes": ["things:read"]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let key_id = resp["id"].as_str().unwrap();

    // Delete the key
    let req = test::TestRequest::delete()
        .uri(&format!("/api/keys/{}", key_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Verify it's gone from the list
    let req = test::TestRequest::get()
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let keys = resp["keys"].as_array().unwrap();
    assert_eq!(keys.len(), 0);
}

#[actix_web::test]
async fn test_delete_nonexistent_api_key() {
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
        .uri("/api/keys/nonexistent-id")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

// ==================== API Key Authentication Tests ====================

#[actix_web::test]
async fn test_api_key_can_access_scoped_endpoints() {
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

    // Create an API key with things:read scope
    let req = test::TestRequest::post()
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Read Only Key",
            "scopes": ["things:read"]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let api_key = resp["key"].as_str().unwrap();

    // Use the API key to list things
    let req = test::TestRequest::get()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", api_key)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success(), "API key should be able to access things:read endpoint");
}

#[actix_web::test]
async fn test_api_key_cannot_access_unscoped_endpoints() {
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

    // Create an API key with only things:read scope (no write)
    let req = test::TestRequest::post()
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Read Only Key",
            "scopes": ["things:read"]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let api_key = resp["key"].as_str().unwrap();

    // Try to create a thing with the read-only key
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", api_key)))
        .set_json(json!({
            "type": "note",
            "content": "Should fail",
            "visibility": "private"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403, "API key without things:write should be forbidden");
}

// ==================== Admin Scope Tests (ported from Go) ====================

#[actix_web::test]
async fn test_api_key_admin_scope() {
    // Test that empty scopes = admin access (can read AND write)
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

    // Create an API key with empty scopes (admin access)
    let req = test::TestRequest::post()
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Admin Key",
            "scopes": []
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let api_key = resp["key"].as_str().unwrap();

    // Admin key should be able to read things
    let req = test::TestRequest::get()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", api_key)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success(), "Admin key should be able to read");

    // Admin key should be able to write things
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", api_key)))
        .set_json(json!({
            "type": "note",
            "content": "Admin test",
            "visibility": "private"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201, "Admin key should be able to write");
}

#[actix_web::test]
async fn test_api_key_kinds_read() {
    // Test that kinds:read scope can access /kinds endpoint
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

    // Create an API key with kinds:read scope
    let req = test::TestRequest::post()
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Kinds Reader",
            "scopes": ["kinds:read"]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let api_key = resp["key"].as_str().unwrap();

    // Should be able to read kinds
    let req = test::TestRequest::get()
        .uri("/api/kinds")
        .insert_header(("Authorization", format!("Bearer {}", api_key)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success(), "kinds:read key should be able to read kinds");
}

#[actix_web::test]
async fn test_api_key_kinds_read_forbidden() {
    // Test that things:read scope cannot access /kinds endpoint
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

    // Create an API key with only things:read scope (no kinds access)
    let req = test::TestRequest::post()
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "No Kinds Access",
            "scopes": ["things:read"]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let api_key = resp["key"].as_str().unwrap();

    // Should NOT be able to read kinds
    let req = test::TestRequest::get()
        .uri("/api/kinds")
        .insert_header(("Authorization", format!("Bearer {}", api_key)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403, "things:read key should be forbidden from reading kinds");
}

// ==================== Get Single API Key Tests ====================

#[actix_web::test]
async fn test_get_api_key() {
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

    // Create a key
    let req = test::TestRequest::post()
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Test Key",
            "scopes": ["things:read"]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let key_id = resp["id"].as_str().unwrap();

    // Get the key by ID
    let req = test::TestRequest::get()
        .uri(&format!("/api/keys/{}", key_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["id"], key_id);
    assert_eq!(resp["name"], "Test Key");
    // key_hash should not be exposed (should be empty or null)
    assert!(
        resp["key_hash"].is_null() || resp["key_hash"].as_str().map(|s| s.is_empty()).unwrap_or(true),
        "key_hash should not be exposed"
    );
}

#[actix_web::test]
async fn test_get_api_key_not_found() {
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
        .uri("/api/keys/nonexistent-id")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

// ==================== Update API Key Tests ====================

#[actix_web::test]
async fn test_update_api_key() {
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

    // Create a key
    let req = test::TestRequest::post()
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Original Name",
            "scopes": ["things:read"]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let key_id = resp["id"].as_str().unwrap();

    // Update the key
    let req = test::TestRequest::put()
        .uri(&format!("/api/keys/{}", key_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Updated Name",
            "scopes": ["things:read", "things:write"]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["name"], "Updated Name");
    let scopes = resp["scopes"].as_array().unwrap();
    assert_eq!(scopes.len(), 2);
    assert!(scopes.contains(&json!("things:read")));
    assert!(scopes.contains(&json!("things:write")));
}

#[actix_web::test]
async fn test_update_api_key_not_found() {
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
        .uri("/api/keys/nonexistent-id")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Updated Name"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}
