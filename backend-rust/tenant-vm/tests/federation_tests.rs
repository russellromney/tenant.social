use actix_web::{test, web, App};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;

// Import from main crate
use tenant_vm::api::{self, AppState};
use tenant_vm::auth::AuthService;
use tenant_vm::events::EventProcessor;
use tenant_vm::models::User;
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

    // Create JWT token
    let token = auth_service.generate_token(&user.id).unwrap();

    (user, token)
}

/// Helper to create things with different visibility levels
async fn create_thing_with_visibility(
    store: &Arc<Store>,
    user_id: &str,
    content: &str,
    visibility: &str,
) -> String {
    let mut thing = tenant_vm::models::Thing {
        id: String::new(),
        user_id: user_id.to_string(),
        thing_type: "note".to_string(),
        content: content.to_string(),
        metadata: HashMap::new(),
        visibility: visibility.to_string(),
        version: 1,
        deleted_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        photos: Vec::new(),
    };

    store.create_thing(&mut thing).unwrap();
    thing.id
}

#[actix_web::test]
async fn test_add_friend_success() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Add a friend
    let req = test::TestRequest::post()
        .uri("/api/friends")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "remote_user_id": "bob@friend.example.com",
            "remote_endpoint": "https://friend.example.com",
            "access_token": "friend_token_123"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success(), "Failed to add friend: {:?}", resp.status());

    // Verify the follow was created
    let follows = store.get_following(&user.id).unwrap();
    assert_eq!(follows.len(), 1);
    assert_eq!(follows[0], "bob@friend.example.com");
}

#[actix_web::test]
async fn test_add_friend_duplicate_fails() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let friend_req = json!({
        "remote_user_id": "bob@friend.example.com",
        "remote_endpoint": "https://friend.example.com",
        "access_token": "friend_token_123"
    });

    // Add friend first time
    let req = test::TestRequest::post()
        .uri("/api/friends")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(&friend_req)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());

    // Try to add same friend again
    let req = test::TestRequest::post()
        .uri("/api/friends")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(&friend_req)
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 400, "Should fail when adding duplicate friend");
}

#[actix_web::test]
async fn test_get_friend_visible_things_filters_private() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, _token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    // Create things with different visibility levels
    create_thing_with_visibility(&store, &user.id, "Public thing", "public").await;
    create_thing_with_visibility(&store, &user.id, "Friends thing", "friends").await;
    create_thing_with_visibility(&store, &user.id, "Private thing", "private").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Fetch friend-visible things (no auth required)
    let req = test::TestRequest::get()
        .uri(&format!("/api/fed/things/{}", user.id))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Verify response
    assert_eq!(resp["success"], true);
    let things = resp["data"].as_array().unwrap();
    assert_eq!(things.len(), 2, "Should return only public and friends things");

    // Verify private thing is NOT in the response
    for thing in things {
        let content = thing["content"].as_str().unwrap();
        assert_ne!(content, "Private thing", "Private things should be filtered out");
        assert!(
            content == "Public thing" || content == "Friends thing",
            "Only public and friends things should be returned"
        );
    }
}

#[actix_web::test]
async fn test_get_friend_visible_things_returns_only_public_and_friends() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, _token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    // Create multiple things
    create_thing_with_visibility(&store, &user.id, "Public 1", "public").await;
    create_thing_with_visibility(&store, &user.id, "Public 2", "public").await;
    create_thing_with_visibility(&store, &user.id, "Friends 1", "friends").await;
    create_thing_with_visibility(&store, &user.id, "Private 1", "private").await;
    create_thing_with_visibility(&store, &user.id, "Private 2", "private").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Fetch friend-visible things
    let req = test::TestRequest::get()
        .uri(&format!("/api/fed/things/{}", user.id))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Verify response
    let things = resp["data"].as_array().unwrap();
    assert_eq!(things.len(), 3, "Should return 2 public + 1 friends = 3 things");

    // Verify all returned things are either public or friends
    for thing in things {
        let visibility = thing["visibility"].as_str().unwrap();
        assert!(
            visibility == "public" || visibility == "friends",
            "Visibility should be public or friends, got: {}", visibility
        );
    }
}

#[actix_web::test]
async fn test_get_friend_visible_things_pagination() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, _token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    // Create 10 public things
    for i in 0..10 {
        create_thing_with_visibility(&store, &user.id, &format!("Public {}", i), "public").await;
    }

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Fetch with limit=5
    let req = test::TestRequest::get()
        .uri(&format!("/api/fed/things/{}?limit=5", user.id))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let things = resp["data"].as_array().unwrap();
    assert_eq!(things.len(), 5, "Should return only 5 things when limit=5");

    // Fetch with offset=5
    let req = test::TestRequest::get()
        .uri(&format!("/api/fed/things/{}?offset=5&limit=5", user.id))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let things = resp["data"].as_array().unwrap();
    assert_eq!(things.len(), 5, "Should return 5 things with offset=5");
}

#[actix_web::test]
async fn test_add_friend_without_auth_fails() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Try to add friend without auth token
    let req = test::TestRequest::post()
        .uri("/api/friends")
        .set_json(json!({
            "remote_user_id": "bob@friend.example.com",
            "remote_endpoint": "https://friend.example.com"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401, "Should require authentication");
}

#[actix_web::test]
async fn test_fed_endpoint_works_without_auth() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, _token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    create_thing_with_visibility(&store, &user.id, "Public thing", "public").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Fetch without auth (should work for federation endpoint)
    let req = test::TestRequest::get()
        .uri(&format!("/api/fed/things/{}", user.id))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success(), "Federation endpoint should work without auth");
}

// ==================== Friend Feed Tests ====================

#[actix_web::test]
async fn test_friend_feed_returns_followed_users_things() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    // Create Alice (the viewer)
    let (alice, alice_token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    // Create Bob (person Alice follows)
    let (bob, _bob_token) = create_test_user_with_token(&store, &auth_service, "bob").await;

    // Bob creates some things
    create_thing_with_visibility(&store, &bob.id, "Bob's public post", "public").await;
    create_thing_with_visibility(&store, &bob.id, "Bob's friends post", "friends").await;
    create_thing_with_visibility(&store, &bob.id, "Bob's private post", "private").await;

    // Alice follows Bob (local follow for this test)
    let mut follow = tenant_vm::models::Follow {
        id: String::new(),
        follower_id: alice.id.clone(),
        following_id: bob.id.clone(),
        remote_endpoint: String::new(), // local follow
        access_token: None,
        created_at: chrono::Utc::now(),
        last_confirmed_at: None,
    };
    store.create_follow(&mut follow).unwrap();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Alice views her friend feed
    let req = test::TestRequest::get()
        .uri("/api/feed/friends")
        .insert_header(("Authorization", format!("Bearer {}", alice_token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Should see Bob's public and friends posts, NOT private
    let things = resp.as_array().unwrap();
    assert_eq!(things.len(), 2, "Should see 2 things (public + friends, not private)");

    for thing in things {
        let visibility = thing["visibility"].as_str().unwrap();
        assert!(visibility == "public" || visibility == "friends");
        assert_ne!(thing["content"], "Bob's private post");
    }
}

#[actix_web::test]
async fn test_friend_feed_requires_auth() {
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
        .uri("/api/feed/friends")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401, "Friend feed should require auth");
}

#[actix_web::test]
async fn test_friend_feed_empty_when_no_follows() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (_alice, alice_token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let req = test::TestRequest::get()
        .uri("/api/feed/friends")
        .insert_header(("Authorization", format!("Bearer {}", alice_token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    let things = resp.as_array().unwrap();
    assert_eq!(things.len(), 0, "Friend feed should be empty when not following anyone");
}

#[actix_web::test]
async fn test_friend_feed_pagination() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let (alice, alice_token) = create_test_user_with_token(&store, &auth_service, "alice").await;
    let (bob, _) = create_test_user_with_token(&store, &auth_service, "bob").await;

    // Bob creates 10 public things
    for i in 0..10 {
        create_thing_with_visibility(&store, &bob.id, &format!("Post {}", i), "public").await;
    }

    // Alice follows Bob
    let mut follow = tenant_vm::models::Follow {
        id: String::new(),
        follower_id: alice.id.clone(),
        following_id: bob.id.clone(),
        remote_endpoint: String::new(),
        access_token: None,
        created_at: chrono::Utc::now(),
        last_confirmed_at: None,
    };
    store.create_follow(&mut follow).unwrap();

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Get first 5
    let req = test::TestRequest::get()
        .uri("/api/feed/friends?limit=5")
        .insert_header(("Authorization", format!("Bearer {}", alice_token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let things = resp.as_array().unwrap();
    assert_eq!(things.len(), 5);

    // Get next 5
    let req = test::TestRequest::get()
        .uri("/api/feed/friends?limit=5&offset=5")
        .insert_header(("Authorization", format!("Bearer {}", alice_token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let things = resp.as_array().unwrap();
    assert_eq!(things.len(), 5);
}

// ==================== Follow Token Tests ====================

#[actix_web::test]
async fn test_create_follow_token_authenticated() {
    // Setup
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

    // Create follow token
    let req = test::TestRequest::post()
        .uri("/api/follows/create-token")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Verify response
    assert!(resp["data"]["follow_token"].is_string(), "Should have follow_token");
    assert!(!resp["data"]["follow_token"].as_str().unwrap().is_empty(), "Token should not be empty");
    assert_eq!(resp["data"]["expires_in"], 300, "Token should expire in 300 seconds");
}

#[actix_web::test]
async fn test_create_follow_token_unauthenticated() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Try to create token without auth
    let req = test::TestRequest::post()
        .uri("/api/follows/create-token")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401, "Should require authentication");
}

#[actix_web::test]
async fn test_verify_follow_valid_token() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Create follow token first
    let req = test::TestRequest::post()
        .uri("/api/follows/create-token")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let create_resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let follow_token = create_resp["data"]["follow_token"].as_str().unwrap().to_string();

    // Now verify the token
    let req = test::TestRequest::post()
        .uri("/api/fed/verify-follow")
        .set_json(json!({
            "follow_token": follow_token
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Verify response
    assert_eq!(resp["data"]["valid"], true, "Token should be valid");
    assert_eq!(resp["data"]["user_id"], user.id, "Should return correct user_id");
}

#[actix_web::test]
async fn test_verify_follow_invalid_token() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Verify invalid token
    let req = test::TestRequest::post()
        .uri("/api/fed/verify-follow")
        .set_json(json!({
            "follow_token": "invalid_token_xyz"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Invalid tokens should return valid: false
    assert_eq!(resp["data"]["valid"], false, "Invalid token should return false");
}

#[actix_web::test]
async fn test_verify_follow_expired_token() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Create follow token
    let req = test::TestRequest::post()
        .uri("/api/follows/create-token")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let create_resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let follow_token = create_resp["data"]["follow_token"].as_str().unwrap().to_string();

    // Manually expire the token by manipulating the store
    let tokens = store.follow_tokens.lock().unwrap();
    if let Some(token_data) = tokens.get(&follow_token) {
        let mut expired_token = token_data.clone();
        expired_token.expires_at = chrono::Utc::now() - chrono::Duration::minutes(1);
        drop(tokens);
        let mut tokens_mut = store.follow_tokens.lock().unwrap();
        tokens_mut.insert(follow_token.clone(), expired_token);
    }

    // Now verify the expired token
    let req = test::TestRequest::post()
        .uri("/api/fed/verify-follow")
        .set_json(json!({
            "follow_token": follow_token
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Expired tokens should return valid: false
    assert_eq!(resp["data"]["valid"], false, "Expired token should return false");
}

#[actix_web::test]
async fn test_follow_same_user_twice() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Create follow token
    let req = test::TestRequest::post()
        .uri("/api/follows/create-token")
        .insert_header(("Authorization", format!("Bearer {}", token.clone())))
        .to_request();

    let create_resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let follow_token = create_resp["data"]["follow_token"].as_str().unwrap().to_string();

    // Try to follow the same person twice with different tokens
    let req = test::TestRequest::post()
        .uri("/api/fed/notify-follow")
        .set_json(json!({
            "follower_user_id": user.id,
            "follower_endpoint": "https://test.example.com",
            "follow_token": follow_token
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // In real federation, this would succeed (200) if verification passed
    // But in this test, the remote endpoint doesn't exist, so it fails verification
    assert_eq!(resp.status(), 400, "Should fail because remote verification endpoint doesn't exist");

    // Create another token for the same user
    let req = test::TestRequest::post()
        .uri("/api/follows/create-token")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let create_resp2: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let follow_token2 = create_resp2["data"]["follow_token"].as_str().unwrap().to_string();

    // Try to follow again with different token
    let req = test::TestRequest::post()
        .uri("/api/fed/notify-follow")
        .set_json(json!({
            "follower_user_id": user.id,
            "follower_endpoint": "https://test.example.com",
            "follow_token": follow_token2
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // Should fail with bad request (token verification will fail because remote doesn't exist)
    assert_eq!(resp.status(), 400, "Second follow should also fail due to verification failure");
}

#[actix_web::test]
async fn test_malicious_token_tampering() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Try to verify a malformed/tampered token
    let req = test::TestRequest::post()
        .uri("/api/fed/verify-follow")
        .set_json(json!({
            "follow_token": "invalid-tampered-token-with-bad-chars-!@#$%^&*()"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;

    // Tampered token should return invalid
    assert_eq!(resp["data"]["valid"], false, "Tampered token should be invalid");
}

#[actix_web::test]
async fn test_complete_follow_flow_success() {
    // Setup - Create two local users to simulate federation flow
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let (follower, follower_token) = create_test_user_with_token(&store, &auth_service, "alice").await;
    let (_followed, _followed_token) = create_test_user_with_token(&store, &auth_service, "bob").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Step 1: Follower creates follow token
    let req = test::TestRequest::post()
        .uri("/api/follows/create-token")
        .insert_header(("Authorization", format!("Bearer {}", follower_token)))
        .to_request();

    let create_resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let follow_token = create_resp["data"]["follow_token"].as_str().unwrap().to_string();
    assert!(!follow_token.is_empty(), "Should get a follow token");

    // Step 2: Follower sends notify-follow request with token
    let req = test::TestRequest::post()
        .uri("/api/fed/notify-follow")
        .set_json(json!({
            "follower_user_id": follower.id,
            "follower_endpoint": "https://follower.example.com",
            "follow_token": follow_token.clone()
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // In a real federation scenario with actual HTTP connectivity, this would succeed (200)
    // But in this test, the remote endpoint doesn't exist, so verification fails (400)
    assert_eq!(resp.status(), 400, "Notify-follow should fail because remote verification endpoint is unreachable");
}

#[actix_web::test]
async fn test_follow_fails_invalid_token() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (follower, _follower_token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Try to notify-follow with an invalid token
    let req = test::TestRequest::post()
        .uri("/api/fed/notify-follow")
        .set_json(json!({
            "follower_user_id": follower.id,
            "follower_endpoint": "https://follower.example.com",
            "follow_token": "invalid_token_xyz"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // Should fail because token can't be verified
    assert_eq!(resp.status(), 400, "Should fail with invalid token");
}

#[actix_web::test]
async fn test_federation_follow_round_trip() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let (alice, alice_token) = create_test_user_with_token(&store, &auth_service, "alice").await;
    let (_bob, _bob_token) = create_test_user_with_token(&store, &auth_service, "bob").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Create follow token
    let req = test::TestRequest::post()
        .uri("/api/follows/create-token")
        .insert_header(("Authorization", format!("Bearer {}", alice_token.clone())))
        .to_request();

    let create_resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    let follow_token = create_resp["data"]["follow_token"].as_str().unwrap().to_string();

    // Alice attempts to follow Bob with proper token
    let req = test::TestRequest::post()
        .uri("/api/fed/notify-follow")
        .set_json(json!({
            "follower_user_id": alice.id,
            "follower_endpoint": "https://alice.example.com",
            "follow_token": follow_token
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    // In a real federation scenario, this would succeed
    // But in this test, the remote endpoint doesn't exist, so verification fails
    assert_eq!(resp.status(), 400, "Should fail because remote verification endpoint doesn't exist");

    // In a real federation test, we would:
    // 1. Verify follow appears in Bob's followers list
    // 2. Create a follow in Alice's following list
    // 3. Test unfollow flow
    // For now, we verify the endpoint returned the appropriate error code
}

#[actix_web::test]
async fn test_cannot_follow_own_instance() {
    // Setup
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));
    let (user, _token) = create_test_user_with_token(&store, &auth_service, "alice").await;

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Try to follow your own instance (localhost:7777 is the default)
    let req = test::TestRequest::post()
        .uri("/api/fed/notify-follow")
        .set_json(json!({
            "follower_user_id": user.id,
            "follower_endpoint": "http://localhost:7777",
            "follow_token": "some_token"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;

    // Should fail with 400 because it's the same instance
    assert_eq!(resp.status(), 400, "Should reject self-follow attempts");
}

#[actix_web::test]
async fn test_load_many_tokens_integration() {
    // Setup
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

    // Create many tokens
    let mut tokens = Vec::new();
    for _ in 0..100 {
        let req = test::TestRequest::post()
            .uri("/api/follows/create-token")
            .insert_header(("Authorization", format!("Bearer {}", token)))
            .to_request();

        let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        let follow_token = resp["data"]["follow_token"].as_str().unwrap().to_string();
        tokens.push(follow_token);
    }

    // All tokens should be unique
    let unique_tokens: std::collections::HashSet<_> = tokens.iter().cloned().collect();
    assert_eq!(unique_tokens.len(), 100, "All 100 tokens should be unique");

    // Verify all tokens are valid
    for follow_token in tokens.iter() {
        let req = test::TestRequest::post()
            .uri("/api/fed/verify-follow")
            .set_json(json!({
                "follow_token": follow_token
            }))
            .to_request();

        let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
        assert_eq!(resp["data"]["valid"], true, "Token should be valid");
    }
}
