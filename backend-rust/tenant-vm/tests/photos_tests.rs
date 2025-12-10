use actix_web::{test, web, App};
use serde_json::json;
use std::sync::Arc;

use tenant_vm::api::{self, AppState};
use tenant_vm::auth::AuthService;
use tenant_vm::events::EventProcessor;
use tenant_vm::models::Photo;
use tenant_vm::store::Store;

fn create_app_state(store: Arc<Store>, auth_service: Arc<AuthService>) -> AppState {
    AppState {
        store: store.clone(),
        auth_service: auth_service.clone(),
        event_processor: Arc::new(EventProcessor::new(store)),
    }
}

/// Helper macro to register a user and get their token and user_id
macro_rules! register_and_get_token_id {
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
        let token = resp["token"].as_str().unwrap().to_string();
        let user_id = resp["user"]["id"].as_str().unwrap().to_string();
        (token, user_id)
    }};
}

/// Helper macro to create a thing and return its ID
macro_rules! create_thing {
    ($app:expr, $token:expr, $content:expr) => {{
        let req = test::TestRequest::post()
            .uri("/api/things")
            .insert_header(("Authorization", format!("Bearer {}", $token)))
            .set_json(json!({
                "type": "note",
                "content": $content,
                "visibility": "private"
            }))
            .to_request();

        let resp: serde_json::Value = test::call_and_read_body_json(&$app, req).await;
        resp["id"].as_str().unwrap().to_string()
    }};
}

#[actix_web::test]
async fn test_update_photo_caption() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Register user and create a thing
    let (token, _user_id) = register_and_get_token_id!(app, "testuser");
    let thing_id = create_thing!(app, &token, "Photo gallery");

    // Create a photo directly in the store
    let mut photo = Photo {
        id: String::new(),
        thing_id: thing_id.clone(),
        caption: "Original caption".to_string(),
        order_index: 0,
        data: vec![0xFF, 0xD8, 0xFF, 0xE0], // JPEG magic bytes
        content_type: "image/jpeg".to_string(),
        filename: "test.jpg".to_string(),
        size: 4,
        created_at: chrono::Utc::now(),
    };
    store.create_photo(&mut photo).unwrap();

    // Update the photo caption
    let req = test::TestRequest::put()
        .uri(&format!("/api/photos/{}", photo.id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "caption": "Updated caption"
        }))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["status"], "ok");

    // Verify caption was updated
    let updated_photo = store.get_photo(&photo.id).unwrap();
    assert_eq!(updated_photo.caption, "Updated caption");
}

#[actix_web::test]
async fn test_update_photo_not_found() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let (token, _) = register_and_get_token_id!(app, "testuser");

    let req = test::TestRequest::put()
        .uri("/api/photos/nonexistent-id")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .set_json(json!({
            "caption": "New caption"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn test_update_photo_without_auth() {
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
        .uri("/api/photos/some-id")
        .set_json(json!({
            "caption": "New caption"
        }))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_web::test]
async fn test_delete_photo() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    // Register user and create a thing
    let (token, _user_id) = register_and_get_token_id!(app, "testuser");
    let thing_id = create_thing!(app, &token, "Photo gallery");

    // Create a photo directly in the store
    let mut photo = Photo {
        id: String::new(),
        thing_id: thing_id.clone(),
        caption: "To be deleted".to_string(),
        order_index: 0,
        data: vec![0xFF, 0xD8, 0xFF, 0xE0],
        content_type: "image/jpeg".to_string(),
        filename: "delete-me.jpg".to_string(),
        size: 4,
        created_at: chrono::Utc::now(),
    };
    store.create_photo(&mut photo).unwrap();
    let photo_id = photo.id.clone();

    // Delete the photo
    let req = test::TestRequest::delete()
        .uri(&format!("/api/photos/{}", photo_id))
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp: serde_json::Value = test::call_and_read_body_json(&app, req).await;
    assert_eq!(resp["status"], "ok");

    // Verify photo is gone
    assert!(store.get_photo(&photo_id).is_err());
}

#[actix_web::test]
async fn test_delete_photo_not_found() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let (token, _) = register_and_get_token_id!(app, "testuser");

    let req = test::TestRequest::delete()
        .uri("/api/photos/nonexistent-id")
        .insert_header(("Authorization", format!("Bearer {}", token)))
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 404);
}

#[actix_web::test]
async fn test_delete_photo_without_auth() {
    let store = Arc::new(Store::new(":memory:").unwrap());
    let auth_service = Arc::new(AuthService::new("test_secret".to_string(), store.clone()));

    let app = test::init_service(
        App::new()
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(create_app_state(store.clone(), auth_service.clone())))
            .configure(api::configure_routes)
    ).await;

    let req = test::TestRequest::delete()
        .uri("/api/photos/some-id")
        .to_request();

    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}
