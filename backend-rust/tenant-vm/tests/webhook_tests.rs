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

// ==================== Webhook Subscription CRUD Tests ====================

#[actix_web::test]
async fn test_create_webhook_subscription() {
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
        .uri("/api/webhooks")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "My Webhook",
            "event_type": "thing.created",
            "action_type": "webhook",
            "action_config": {
                "url": "https://example.com/webhook",
                "method": "POST"
            },
            "enabled": true
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["name"], "My Webhook");
    assert_eq!(resp["event_type"], "thing.created");
    assert_eq!(resp["action_type"], "webhook");
    assert!(resp["id"].is_string());
}

#[actix_web::test]
async fn test_list_webhook_subscriptions() {
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

    // Create multiple webhooks
    for i in 0..3 {
        let req = test::TestRequest::post()
            .uri("/api/webhooks")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "name": format!("Webhook {}", i),
                "event_type": "thing.created",
                "action_type": "webhook",
                "action_config": {
                    "url": format!("https://example.com/webhook{}", i)
                },
                "enabled": true
            }))
            .to_request();
        test::call_service(&app, req).await;
    }

    // List all webhooks
    let req = test::TestRequest::get()
        .uri("/api/webhooks")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    // API returns array directly, not wrapped in { webhooks: [...] }
    let webhooks = resp.as_array().unwrap();
    assert_eq!(webhooks.len(), 3);
}

#[actix_web::test]
async fn test_get_webhook_subscription() {
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

    // Create a webhook
    let req = test::TestRequest::post()
        .uri("/api/webhooks")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Test Webhook",
            "event_type": "thing.updated",
            "action_type": "webhook",
            "action_config": {
                "url": "https://example.com/webhook"
            },
            "enabled": true
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let webhook_id = resp["id"].as_str().unwrap();

    // Get the webhook by ID
    let req = test::TestRequest::get()
        .uri(&format!("/api/webhooks/{}", webhook_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["id"], webhook_id);
    assert_eq!(resp["name"], "Test Webhook");
    assert_eq!(resp["event_type"], "thing.updated");
}

#[actix_web::test]
async fn test_update_webhook_subscription() {
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

    // Create a webhook
    let req = test::TestRequest::post()
        .uri("/api/webhooks")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Original Name",
            "event_type": "thing.created",
            "action_type": "webhook",
            "action_config": {
                "url": "https://example.com/old"
            },
            "enabled": true
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let webhook_id = resp["id"].as_str().unwrap();

    // Update the webhook
    let req = test::TestRequest::put()
        .uri(&format!("/api/webhooks/{}", webhook_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Updated Name",
            "event_type": "thing.deleted",
            "action_config": {
                "url": "https://example.com/new"
            },
            "enabled": false
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["name"], "Updated Name");
    assert_eq!(resp["event_type"], "thing.deleted");
    assert_eq!(resp["enabled"], false);
}

#[actix_web::test]
async fn test_delete_webhook_subscription() {
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

    // Create a webhook
    let req = test::TestRequest::post()
        .uri("/api/webhooks")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "To Delete",
            "event_type": "thing.created",
            "action_type": "webhook",
            "action_config": {
                "url": "https://example.com/webhook"
            },
            "enabled": true
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let webhook_id = resp["id"].as_str().unwrap();

    // Delete the webhook
    let req = test::TestRequest::delete()
        .uri(&format!("/api/webhooks/{}", webhook_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Verify it's gone
    let req = test::TestRequest::get()
        .uri(&format!("/api/webhooks/{}", webhook_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn test_webhook_requires_auth() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Try to list webhooks without auth
    let req = test::TestRequest::get()
        .uri("/api/webhooks")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_webhook_with_signing_secret() {
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

    // Create a webhook with signing secret
    let req = test::TestRequest::post()
        .uri("/api/webhooks")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Signed Webhook",
            "event_type": "thing.created",
            "action_type": "webhook",
            "action_config": {
                "url": "https://example.com/webhook",
                "signing_secret": "my-secret-key"
            },
            "enabled": true
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["name"], "Signed Webhook");
    // Verify signing_secret is in action_config
    assert_eq!(resp["action_config"]["signing_secret"], "my-secret-key");
}

// ==================== Source Attribution Tests ====================

#[actix_web::test]
async fn test_create_thing_with_source() {
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

    // Create a thing with source attribution
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "Imported content",
            "visibility": "private",
            "source": {
                "system": "github",
                "external_id": "issue-123",
                "url": "https://github.com/user/repo/issues/123"
            }
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["content"], "Imported content");
    assert_eq!(resp["source"]["system"], "github");
    assert_eq!(resp["source"]["external_id"], "issue-123");
    assert_eq!(resp["source"]["url"], "https://github.com/user/repo/issues/123");
    assert!(resp["source"]["imported_at"].is_string());
}

#[actix_web::test]
async fn test_create_thing_without_source() {
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

    // Create a thing without source
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "Native content",
            "visibility": "private"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["content"], "Native content");
    // Source should be null or not present
    assert!(resp["source"].is_null() || !resp.as_object().unwrap().contains_key("source"));
}

#[actix_web::test]
async fn test_query_things_by_source_system() {
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

    // Create things from different sources
    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "From GitHub",
            "visibility": "private",
            "source": {
                "system": "github",
                "external_id": "issue-1"
            }
        }))
        .to_request();
    test::call_service(&app, req).await;

    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "From Twitter",
            "visibility": "private",
            "source": {
                "system": "twitter",
                "external_id": "tweet-1"
            }
        }))
        .to_request();
    test::call_service(&app, req).await;

    let req = test::TestRequest::post()
        .uri("/api/things")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "type": "note",
            "content": "Native",
            "visibility": "private"
        }))
        .to_request();
    test::call_service(&app, req).await;

    // Query for github-sourced things
    let req = test::TestRequest::get()
        .uri("/api/things?source_system=github")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    // API returns array directly
    let things = resp.as_array().unwrap();

    assert_eq!(things.len(), 1);
    assert_eq!(things[0]["content"], "From GitHub");
}

// ==================== Inbound Webhook Tests ====================

#[actix_web::test]
async fn test_create_inbound_webhook() {
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
        .uri("/api/webhooks/inbound")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "GitHub Importer",
            "default_thing_type": "note",
            "default_visibility": "private",
            "source_system": "github"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["name"], "GitHub Importer");
    assert_eq!(resp["source_system"], "github");
    assert!(resp["id"].is_string());
    // Should return secret_token on creation
    assert!(resp["secret_token"].is_string());
    // Should show token prefix
    assert!(resp["token_prefix"].is_string());
}

#[actix_web::test]
async fn test_list_inbound_webhooks() {
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

    // Create multiple inbound webhooks
    for i in 0..2 {
        let req = test::TestRequest::post()
            .uri("/api/webhooks/inbound")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .set_json(json!({
                "name": format!("Importer {}", i),
                "default_thing_type": "note",
                "default_visibility": "private",
                "source_system": format!("source{}", i)
            }))
            .to_request();
        test::call_service(&app, req).await;
    }

    // List all inbound webhooks
    let req = test::TestRequest::get()
        .uri("/api/webhooks/inbound")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    // API returns array directly
    let webhooks = resp.as_array().unwrap();
    assert_eq!(webhooks.len(), 2);
}

#[actix_web::test]
async fn test_receive_webhook_creates_thing() {
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

    // Create an inbound webhook
    let req = test::TestRequest::post()
        .uri("/api/webhooks/inbound")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Test Receiver",
            "default_thing_type": "note",
            "default_visibility": "private",
            "source_system": "external-api"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let webhook_id = resp["id"].as_str().unwrap();
    let webhook_token = resp["secret_token"].as_str().unwrap();

    // Send a payload to the receive endpoint
    let req = test::TestRequest::post()
        .uri(&format!("/api/webhooks/receive/{}?token={}", webhook_id, webhook_token))
        .set_json(json!({
            "content": "Received via webhook",
            "external_id": "ext-123"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["content"], "Received via webhook");
    assert_eq!(resp["source"]["system"], "external-api");
    assert_eq!(resp["source"]["external_id"], "ext-123");
}

#[actix_web::test]
async fn test_receive_webhook_requires_valid_token() {
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

    // Create an inbound webhook
    let req = test::TestRequest::post()
        .uri("/api/webhooks/inbound")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Test Receiver",
            "default_thing_type": "note",
            "default_visibility": "private",
            "source_system": "external-api"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let webhook_id = resp["id"].as_str().unwrap();

    // Try to send with wrong token
    let req = test::TestRequest::post()
        .uri(&format!("/api/webhooks/receive/{}?token=wrong-token", webhook_id))
        .set_json(json!({
            "content": "Should fail",
            "external_id": "ext-456"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_receive_webhook_deduplication() {
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

    // Create an inbound webhook
    let req = test::TestRequest::post()
        .uri("/api/webhooks/inbound")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Dedup Test",
            "default_thing_type": "note",
            "default_visibility": "private",
            "source_system": "dedup-source"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let webhook_id = resp["id"].as_str().unwrap();
    let webhook_token = resp["secret_token"].as_str().unwrap();

    // Send the same payload twice with same external_id
    for _ in 0..2 {
        let req = test::TestRequest::post()
            .uri(&format!("/api/webhooks/receive/{}?token={}", webhook_id, webhook_token))
            .set_json(json!({
                "content": "Deduplicated content",
                "external_id": "same-id-123"
            }))
            .to_request();
        test::call_service(&app, req).await;
    }

    // Check that only one thing was created
    let req = test::TestRequest::get()
        .uri("/api/things?source_system=dedup-source")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    // API returns array directly
    let things = resp.as_array().unwrap();

    assert_eq!(things.len(), 1, "Duplicate external_id should not create multiple things");
}

#[actix_web::test]
async fn test_delete_inbound_webhook() {
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

    // Create an inbound webhook
    let req = test::TestRequest::post()
        .uri("/api/webhooks/inbound")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "To Delete",
            "default_thing_type": "note",
            "default_visibility": "private",
            "source_system": "delete-test"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let webhook_id = resp["id"].as_str().unwrap();

    // Delete the webhook
    let req = test::TestRequest::delete()
        .uri(&format!("/api/webhooks/inbound/{}", webhook_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Verify it's gone
    let req = test::TestRequest::get()
        .uri(&format!("/api/webhooks/inbound/{}", webhook_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

// ==================== HMAC Signature Tests ====================

#[cfg(test)]
mod hmac_tests {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    /// Test that we can compute HMAC signatures correctly
    #[test]
    fn test_hmac_signature_computation() {
        let secret = "my-signing-secret";
        let payload = r#"{"event":"thing.created","data":{"id":"123"}}"#;

        let mut mac = HmacSha256::new_from_slice(secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac.update(payload.as_bytes());
        let result = mac.finalize();
        let signature = hex::encode(result.into_bytes());

        // Verify the signature is a valid hex string of correct length (SHA-256 = 64 hex chars)
        assert_eq!(signature.len(), 64);
        assert!(signature.chars().all(|c| c.is_ascii_hexdigit()));

        // Verify the same input produces the same output
        let mut mac2 = HmacSha256::new_from_slice(secret.as_bytes())
            .expect("HMAC can take key of any size");
        mac2.update(payload.as_bytes());
        let result2 = mac2.finalize();
        let signature2 = hex::encode(result2.into_bytes());

        assert_eq!(signature, signature2);
    }

    /// Test that different secrets produce different signatures
    #[test]
    fn test_hmac_different_secrets() {
        let payload = r#"{"event":"thing.created"}"#;

        let mut mac1 = HmacSha256::new_from_slice(b"secret1")
            .expect("HMAC can take key of any size");
        mac1.update(payload.as_bytes());
        let sig1 = hex::encode(mac1.finalize().into_bytes());

        let mut mac2 = HmacSha256::new_from_slice(b"secret2")
            .expect("HMAC can take key of any size");
        mac2.update(payload.as_bytes());
        let sig2 = hex::encode(mac2.finalize().into_bytes());

        assert_ne!(sig1, sig2);
    }

    /// Test that different payloads produce different signatures
    #[test]
    fn test_hmac_different_payloads() {
        let secret = b"my-secret";

        let mut mac1 = HmacSha256::new_from_slice(secret)
            .expect("HMAC can take key of any size");
        mac1.update(b"payload1");
        let sig1 = hex::encode(mac1.finalize().into_bytes());

        let mut mac2 = HmacSha256::new_from_slice(secret)
            .expect("HMAC can take key of any size");
        mac2.update(b"payload2");
        let sig2 = hex::encode(mac2.finalize().into_bytes());

        assert_ne!(sig1, sig2);
    }
}

// ==================== API Key Scope Tests for Webhooks ====================

#[actix_web::test]
async fn test_webhook_api_key_read_scope() {
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

    // Create an API key with webhooks:read scope
    let req = test::TestRequest::post()
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Webhook Reader",
            "scopes": ["webhooks:read"]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let api_key = resp["key"].as_str().unwrap();

    // Should be able to list webhooks
    let req = test::TestRequest::get()
        .uri("/api/webhooks")
        .insert_header(("Authorization", format!("Bearer {}", api_key)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success(), "webhooks:read key should be able to list webhooks");
}

#[actix_web::test]
async fn test_webhook_api_key_write_scope_required() {
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

    // Create an API key with only webhooks:read scope (no write)
    let req = test::TestRequest::post()
        .uri("/api/keys")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "name": "Read Only Webhook Key",
            "scopes": ["webhooks:read"]
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let api_key = resp["key"].as_str().unwrap();

    // Try to create a webhook with read-only key
    let req = test::TestRequest::post()
        .uri("/api/webhooks")
        .insert_header(("Authorization", format!("Bearer {}", api_key)))
        .set_json(json!({
            "name": "Should Fail",
            "event_type": "thing.created",
            "action_type": "webhook",
            "action_config": {
                "url": "https://example.com"
            },
            "enabled": true
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 403, "webhooks:read key should not be able to create webhooks");
}
