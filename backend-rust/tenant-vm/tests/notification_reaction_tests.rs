use actix_web::{test, web, App};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

use tenant_vm::api::{self, AppState};
use tenant_vm::auth::AuthService;
use tenant_vm::events::EventProcessor;
use tenant_vm::models::{Notification, User};
use tenant_vm::store::Store;

/// Helper to create AppState with all required components
fn create_app_state(store: Arc<Store>, auth_service: Arc<AuthService>) -> AppState {
    AppState {
        store: store.clone(),
        auth_service: auth_service.clone(),
        event_processor: Arc::new(EventProcessor::new(store)),
    }
}

/// Helper to create a test user and return their auth token
async fn create_test_user_with_token(store: &Arc<Store>, auth_service: &Arc<AuthService>, username: &str) -> (User, String) {
    let password_hash = auth_service.hash_password("testpass123").unwrap();

    let mut user = User {
        id: String::new(),
        username: username.to_string(),
        email: format!("{}@test.com", username),
        password_hash,
        display_name: username.to_string(),
        bio: String::new(),
        avatar_url: String::new(),
        is_admin: false,
        is_locked: false,
        recovery_hash: String::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    store.create_user(&mut user).unwrap();
    let token = auth_service.generate_token(&user.id).unwrap();
    (user, token)
}

/// Helper to create a test thing
async fn create_test_thing(store: &Arc<Store>, user_id: &str, content: &str) -> String {
    let mut thing = tenant_vm::models::Thing {
        id: String::new(),
        user_id: user_id.to_string(),
        thing_type: "note".to_string(),
        content: content.to_string(),
        metadata: HashMap::new(),
        visibility: "public".to_string(),
        version: 1,
        deleted_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        photos: Vec::new(),
    };

    store.create_thing(&mut thing).unwrap();
    thing.id
}

/// Helper to create a test notification
fn create_test_notification(store: &Arc<Store>, user_id: &str, notif_type: &str, title: &str) -> String {
    let notification = Notification {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: user_id.to_string(),
        notification_type: notif_type.to_string(),
        actor_id: Some("remote_user@example.com".to_string()),
        actor_type: Some("remote".to_string()),
        resource_type: Some("thing".to_string()),
        resource_id: Some("thing_123".to_string()),
        title: Some(title.to_string()),
        body: Some("Test body".to_string()),
        url: Some("https://example.com".to_string()),
        metadata: None,
        read: false,
        created_at: chrono::Utc::now(),
    };

    store.create_notification(&notification).unwrap();
    notification.id
}

// ==================== Notification Tests ====================

#[actix_web::test]
async fn test_list_notifications() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    // Create some notifications
    create_test_notification(&store, &user.id, "like", "Someone liked your post");
    create_test_notification(&store, &user.id, "follow", "Someone followed you");
    create_test_notification(&store, &user.id, "comment", "Someone commented");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let req = test::TestRequest::get()
        .uri("/api/notifications")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    assert_eq!(resp["success"], true);
    let notifications = resp["data"]["notifications"].as_array().unwrap();
    assert_eq!(notifications.len(), 3);
    assert_eq!(resp["data"]["total"], 3);
    assert_eq!(resp["data"]["unread"], 3);
}

#[actix_web::test]
async fn test_notifications_pagination() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    // Create 10 notifications
    for i in 0..10 {
        create_test_notification(&store, &user.id, "like", &format!("Notification {}", i));
    }

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Get first page (limit 5)
    let req = test::TestRequest::get()
        .uri("/api/notifications?limit=5")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let notifications = resp["data"]["notifications"].as_array().unwrap();
    assert_eq!(notifications.len(), 5);

    // Get second page
    let req = test::TestRequest::get()
        .uri("/api/notifications?limit=5&offset=5")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let notifications = resp["data"]["notifications"].as_array().unwrap();
    assert_eq!(notifications.len(), 5);
}

#[actix_web::test]
async fn test_get_unread_count() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    create_test_notification(&store, &user.id, "like", "Test 1");
    create_test_notification(&store, &user.id, "like", "Test 2");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let req = test::TestRequest::get()
        .uri("/api/notifications/unread-count")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["success"], true);
    assert_eq!(resp["data"]["count"], 2);
}

#[actix_web::test]
async fn test_mark_notification_read() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let notif_id = create_test_notification(&store, &user.id, "like", "Test notification");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Verify unread count is 1
    let req = test::TestRequest::get()
        .uri("/api/notifications/unread-count")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["data"]["count"], 1);

    // Mark as read
    let req = test::TestRequest::put()
        .uri(&format!("/api/notifications/{}/read", notif_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Verify unread count is now 0
    let req = test::TestRequest::get()
        .uri("/api/notifications/unread-count")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["data"]["count"], 0);
}

#[actix_web::test]
async fn test_mark_all_notifications_read() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    // Create multiple unread notifications
    for i in 0..5 {
        create_test_notification(&store, &user.id, "like", &format!("Test {}", i));
    }

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Verify we have 5 unread
    let req = test::TestRequest::get()
        .uri("/api/notifications/unread-count")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["data"]["count"], 5);

    // Mark all as read
    let req = test::TestRequest::put()
        .uri("/api/notifications/read-all")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["success"], true);
    assert_eq!(resp["data"]["marked_read"], 5);

    // Verify unread count is 0
    let req = test::TestRequest::get()
        .uri("/api/notifications/unread-count")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();
    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["data"]["count"], 0);
}

#[actix_web::test]
async fn test_delete_notification() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let notif_id = create_test_notification(&store, &user.id, "like", "Test notification");

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Delete the notification
    let req = test::TestRequest::delete()
        .uri(&format!("/api/notifications/{}", notif_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Verify notification is gone
    let req = test::TestRequest::get()
        .uri("/api/notifications")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let notifications = resp["data"]["notifications"].as_array().unwrap();
    assert_eq!(notifications.len(), 0);
}

#[actix_web::test]
async fn test_notification_settings() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (_user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Update settings to disable "like" notifications
    let req = test::TestRequest::put()
        .uri("/api/notifications/settings")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "notification_type": "like",
            "enabled": false
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["success"], true);
    assert_eq!(resp["data"]["enabled"], false);

    // Get all settings
    let req = test::TestRequest::get()
        .uri("/api/notifications/settings")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["success"], true);
    let settings = resp["data"].as_array().unwrap();
    assert!(settings.len() >= 1);
}

#[actix_web::test]
async fn test_notifications_require_auth() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Try to list notifications without auth
    let req = test::TestRequest::get()
        .uri("/api/notifications")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

// ==================== Reaction Tests ====================

#[actix_web::test]
async fn test_add_reaction() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let thing_id = create_test_thing(&store, &user.id, "Test post").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Add a like reaction
    let req = test::TestRequest::post()
        .uri(&format!("/api/things/{}/reactions", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({ "type": "like" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status();
    if !status.is_success() {
        let body = test::read_body(resp).await;
        let body_str = String::from_utf8_lossy(&body);
        panic!("Failed with status {}: {}", status, body_str);
    }
    assert_eq!(status, 201);
}

#[actix_web::test]
async fn test_add_emoji_reaction() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let thing_id = create_test_thing(&store, &user.id, "Test post").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Add a fire emoji reaction (actual emoji)
    let req = test::TestRequest::post()
        .uri(&format!("/api/things/{}/reactions", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({ "type": "🔥" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    let status = resp.status();
    if !status.is_success() {
        let body = test::read_body(resp).await;
        let body_str = String::from_utf8_lossy(&body);
        panic!("Failed with status {}: {}", status, body_str);
    }
    assert_eq!(status, 201);
}

#[actix_web::test]
async fn test_add_invalid_reaction_fails() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let thing_id = create_test_thing(&store, &user.id, "Test post").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Try to add an invalid reaction type
    let req = test::TestRequest::post()
        .uri(&format!("/api/things/{}/reactions", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({ "type": "invalid_reaction" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400);
}

#[actix_web::test]
async fn test_duplicate_reaction_fails() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let thing_id = create_test_thing(&store, &user.id, "Test post").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Add a like
    let req = test::TestRequest::post()
        .uri(&format!("/api/things/{}/reactions", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({ "type": "like" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 201);

    // Try to add the same reaction again
    let req = test::TestRequest::post()
        .uri(&format!("/api/things/{}/reactions", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({ "type": "like" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 409, "Should conflict when adding duplicate reaction");
}

#[actix_web::test]
async fn test_remove_reaction() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let thing_id = create_test_thing(&store, &user.id, "Test post").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Add a like
    let req = test::TestRequest::post()
        .uri(&format!("/api/things/{}/reactions", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({ "type": "like" }))
        .to_request();

    test::call_service(&app, req).await;

    // Remove the like
    let req = test::TestRequest::delete()
        .uri(&format!("/api/things/{}/reactions/like", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Verify reaction is gone
    let req = test::TestRequest::get()
        .uri(&format!("/api/things/{}/reactions", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let counts = resp["data"]["counts"].as_object().unwrap();
    let total: i64 = counts.values().map(|v| v.as_i64().unwrap_or(0)).sum();
    assert_eq!(total, 0);
}

#[actix_web::test]
async fn test_get_reactions() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;
    let (_user2, token2) = create_test_user_with_token(&store, &auth_service, "bob").await;

    let thing_id = create_test_thing(&store, &user.id, "Test post").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // User 1 adds a like
    let req = test::TestRequest::post()
        .uri(&format!("/api/things/{}/reactions", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({ "type": "like" }))
        .to_request();
    test::call_service(&app, req).await;

    // User 2 adds a like and emoji
    let req = test::TestRequest::post()
        .uri(&format!("/api/things/{}/reactions", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token2)))
        .set_json(json!({ "type": "like" }))
        .to_request();
    test::call_service(&app, req).await;

    let req = test::TestRequest::post()
        .uri(&format!("/api/things/{}/reactions", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token2)))
        .set_json(json!({ "type": "fire" }))
        .to_request();
    test::call_service(&app, req).await;

    // Get reactions as user 1
    let req = test::TestRequest::get()
        .uri(&format!("/api/things/{}/reactions", thing_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["success"], true);

    let counts = &resp["data"]["counts"];
    assert_eq!(counts["like"], 2);
    assert_eq!(counts["fire"], 1);

    // User 1 should see their own reaction
    let user_reactions = resp["data"]["user_reactions"].as_array().unwrap();
    assert!(user_reactions.contains(&json!("like")));
}

#[actix_web::test]
async fn test_reactions_require_auth() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, _token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let thing_id = create_test_thing(&store, &user.id, "Test post").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Try to add reaction without auth
    let req = test::TestRequest::post()
        .uri(&format!("/api/things/{}/reactions", thing_id))
        .set_json(json!({ "type": "like" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_reaction_on_nonexistent_thing_fails() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (_user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Try to add reaction to non-existent thing
    let req = test::TestRequest::post()
        .uri("/api/things/nonexistent-id/reactions")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({ "type": "like" }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

// ==================== Cross-Node Notification Tests ====================

#[actix_web::test]
async fn test_inbound_notification_accepted() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    // Create an "owner" user (the one who receives inbound notifications)
    let password_hash = auth_service.hash_password("password").unwrap();
    let mut owner = User {
        id: String::new(),
        username: "owner".to_string(), // Must match OWNER_USERNAME env var default
        email: "owner@test.com".to_string(),
        password_hash,
        display_name: "Owner".to_string(),
        bio: String::new(),
        avatar_url: String::new(),
        is_admin: true,
        is_locked: false,
        recovery_hash: String::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store.create_user(&mut owner).unwrap();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Send an inbound notification (no auth required - from remote node)
    let req = test::TestRequest::post()
        .uri("/api/notifications/inbound")
        .set_json(json!({
            "notification_type": "like",
            "actor_id": "bob@remote.example.com",
            "actor_type": "remote",
            "resource_type": "thing",
            "resource_id": "thing_abc",
            "title": "Bob liked your post",
            "body": "Bob liked your post about Rust",
            "url": "https://remote.example.com/things/thing_abc"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["status"], "accepted");

    // Verify the notification was created
    let notifications = store.list_notifications(&owner.id, 10, 0).unwrap();
    assert_eq!(notifications.len(), 1);
    assert_eq!(notifications[0].notification_type, "like");
    assert_eq!(notifications[0].actor_id, Some("bob@remote.example.com".to_string()));
}

#[actix_web::test]
async fn test_inbound_notification_rejected_by_settings() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    // Create an "owner" user
    let password_hash = auth_service.hash_password("password").unwrap();
    let mut owner = User {
        id: String::new(),
        username: "owner".to_string(),
        email: "owner@test.com".to_string(),
        password_hash,
        display_name: "Owner".to_string(),
        bio: String::new(),
        avatar_url: String::new(),
        is_admin: true,
        is_locked: false,
        recovery_hash: String::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };
    store.create_user(&mut owner).unwrap();

    // Disable "spam" notifications
    store.update_notification_settings(&owner.id, "spam", false).unwrap();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Send an inbound notification of type "spam"
    let req = test::TestRequest::post()
        .uri("/api/notifications/inbound")
        .set_json(json!({
            "notification_type": "spam",
            "actor_id": "spammer@bad.com",
            "actor_type": "remote",
            "title": "Buy now!",
            "body": "Amazing deals"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["status"], "rejected");

    // Verify no notification was created
    let notifications = store.list_notifications(&owner.id, 10, 0).unwrap();
    assert_eq!(notifications.len(), 0);
}
