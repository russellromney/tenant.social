use actix_multipart::Multipart;
use actix_web::{cookie::{Cookie, SameSite, time::Duration}, web, HttpResponse, HttpRequest, Responder};
use chrono::Utc;
use futures_util::StreamExt;
use serde::Deserialize;
use std::collections::HashMap;
use std::env;
use std::sync::Arc;

use crate::auth::{has_scope, AuthService, AuthUser};
use crate::events::EventProcessor;
use crate::models::*;
use crate::store::{Store, StoreError};

// Cookie settings - 6 months in seconds
const COOKIE_MAX_AGE_SECONDS: i64 = 6 * 30 * 24 * 60 * 60;

pub struct AppState {
    pub store: Arc<Store>,
    pub auth_service: Arc<AuthService>,
    pub event_processor: Arc<EventProcessor>,
}

// ==================== Health Check ====================

pub async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "timestamp": Utc::now().to_rfc3339()
    }))
}

// ==================== Auth Status ====================

pub async fn auth_status(state: web::Data<AppState>) -> impl Responder {
    // Check if running in sandbox mode
    let sandbox_mode = env::var("SANDBOX_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

    // In sandbox mode, return the actual sandbox user from database
    if sandbox_mode {
        match state.store.get_user_by_username("sandbox") {
            Ok(user) => {
                return HttpResponse::Ok().json(serde_json::json!({
                    "hasOwner": true,
                    "registrationEnabled": false,
                    "sandboxMode": true,
                    "authDisabled": false,
                    "user": {
                        "id": user.id,
                        "username": user.username
                    }
                }));
            }
            Err(_) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({
                    "error": "Sandbox user not found"
                }));
            }
        }
    }

    // Dynamic status based on actual user count (matches Go behavior)
    let user_count = state.store.count_users().unwrap_or(0);
    let has_owner = user_count > 0;
    let registration_enabled = user_count == 0; // Only enable registration if no users exist

    HttpResponse::Ok().json(serde_json::json!({
        "hasOwner": has_owner,
        "registrationEnabled": registration_enabled,
        "sandboxMode": false,
        "authDisabled": false
    }))
}

// ==================== Auth Endpoints ====================

pub async fn register(
    state: web::Data<AppState>,
    body: web::Json<RegisterRequest>,
) -> impl Responder {
    // Single-tenant enforcement: reject if any user exists (matches Go behavior)
    let user_count = match state.store.count_users() {
        Ok(count) => count,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Database error"})),
    };

    if user_count > 0 {
        return HttpResponse::Forbidden().json(serde_json::json!({
            "error": "Registration disabled - this is a single-tenant instance"
        }));
    }

    // Validate username length (3-30 characters like Go)
    if body.username.len() < 3 || body.username.len() > 30 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Username must be between 3 and 30 characters"
        }));
    }

    let password_hash = match state.auth_service.hash_password(&body.password) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to hash password"})),
    };

    // First user becomes admin (matches Go behavior)
    let is_admin = user_count == 0;

    let mut user = User {
        id: String::new(),
        username: body.username.clone(),
        email: body.email.clone(),
        password_hash,
        display_name: body.display_name.clone().unwrap_or_else(|| body.username.clone()),
        bio: String::new(),
        avatar_url: String::new(),
        is_admin,
        is_locked: false,
        recovery_hash: String::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    if let Err(e) = state.store.create_user(&mut user) {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("Failed to create user: {}", e)}));
    }

    let token = match state.auth_service.generate_token(&user.id) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to generate token"})),
    };

    // Set auth cookie for browser sessions
    let cookie = Cookie::build("tenant_auth", token.clone())
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(COOKIE_MAX_AGE_SECONDS))
        .finish();

    // Return direct object (not ApiResponse wrapper) to match Go
    HttpResponse::Created()
        .cookie(cookie)
        .json(serde_json::json!({
            "user": user,
            "token": token
        }))
}

pub async fn login(
    state: web::Data<AppState>,
    body: web::Json<LoginRequest>,
) -> impl Responder {
    // Support login with username OR email (like Go - check for @ symbol)
    let user = if body.username.contains('@') {
        // Email login
        match state.store.get_user_by_email(&body.username) {
            Ok(u) => u,
            Err(StoreError::NotFound(_)) => {
                return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"}));
            }
            Err(_) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Database error"}));
            }
        }
    } else {
        // Username login
        match state.store.get_user_by_username(&body.username) {
            Ok(u) => u,
            Err(StoreError::NotFound(_)) => {
                return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"}));
            }
            Err(_) => {
                return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Database error"}));
            }
        }
    };

    // Return 401 for locked accounts (matches Go behavior)
    if user.is_locked {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Account is locked"}));
    }

    let valid = state.auth_service
        .verify_password(&body.password, &user.password_hash)
        .unwrap_or(false);

    if !valid {
        return HttpResponse::Unauthorized().json(serde_json::json!({"error": "Invalid credentials"}));
    }

    let token = match state.auth_service.generate_token(&user.id) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to generate token"})),
    };

    // Set auth cookie for browser sessions
    let cookie = Cookie::build("tenant_auth", token.clone())
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(COOKIE_MAX_AGE_SECONDS))
        .finish();

    // Return direct object (not ApiResponse wrapper) to match Go
    HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({
            "user": user,
            "token": token
        }))
}

pub async fn get_current_user(
    state: web::Data<AppState>,
    auth_user: AuthUser,
) -> impl Responder {
    match state.store.get_user(&auth_user.user_id) {
        // Return user directly (matches Go behavior)
        Ok(user) => HttpResponse::Ok().json(user),
        Err(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    }
}

pub async fn logout() -> impl Responder {
    // Clear auth cookie by setting it to empty with immediate expiration
    let cookie = Cookie::build("tenant_auth", "")
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(0))
        .finish();

    // Return simple status object (matches Go behavior)
    HttpResponse::Ok()
        .cookie(cookie)
        .json(serde_json::json!({"status": "ok"}))
}

// ==================== Public Endpoints ====================

#[derive(Deserialize)]
pub struct PaginationQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

pub async fn get_public_profile(state: web::Data<AppState>) -> impl Responder {
    match state.store.get_owner_profile() {
        Ok(user) => HttpResponse::Ok().json(user),
        Err(StoreError::NotFound(_)) => {
            HttpResponse::NotFound().json(serde_json::json!({"error": "Owner profile not found"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to get owner profile: {}", e)})),
    }
}

pub async fn get_public_things(
    state: web::Data<AppState>,
    query: web::Query<PaginationQuery>,
) -> impl Responder {
    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    match state.store.get_public_things(limit, offset) {
        Ok(things) => HttpResponse::Ok().json(things),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to get public things: {}", e)})),
    }
}

// ==================== Things Endpoints ====================

#[derive(Deserialize)]
pub struct ListThingsQuery {
    #[serde(rename = "type")]
    thing_type: Option<String>,
    limit: Option<i64>,
    offset: Option<i64>,
}

pub async fn list_things(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    query: web::Query<ListThingsQuery>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:read") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: things:read"}));
    }

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    match state.store.list_things(&auth_user.user_id, query.thing_type.as_deref(), limit, offset) {
        Ok(things) => HttpResponse::Ok().json(things), // Return plain array
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to list things: {}", e)})),
    }
}

pub async fn get_thing(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:read") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: things:read"}));
    }

    let id = path.into_inner();
    match state.store.get_thing(&id) {
        Ok(thing) => {
            // Check ownership
            if thing.user_id != auth_user.user_id {
                return HttpResponse::NotFound().json(serde_json::json!({"error": "Thing not found"}));
            }
            HttpResponse::Ok().json(thing) // Return plain object
        }
        Err(StoreError::NotFound(_)) => {
            HttpResponse::NotFound().json(serde_json::json!({"error": "Thing not found"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to get thing: {}", e)})),
    }
}

pub async fn create_thing(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    body: web::Json<CreateThingRequest>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: things:write"}));
    }

    let mut thing = Thing {
        id: String::new(),
        user_id: auth_user.user_id.clone(),
        thing_type: body.thing_type.clone(),
        content: body.content.clone(),
        metadata: body.metadata.clone(),
        visibility: body.visibility.clone(),
        version: 0,
        deleted_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        photos: Vec::new(),
    };

    match state.store.create_thing(&mut thing) {
        Ok(_) => HttpResponse::Created().json(thing), // Return plain object
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to create thing: {}", e)})),
    }
}

pub async fn update_thing(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
    body: web::Json<UpdateThingRequest>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: things:write"}));
    }

    let id = path.into_inner();
    let mut thing = match state.store.get_thing(&id) {
        Ok(t) => t,
        Err(StoreError::NotFound(_)) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "Thing not found"}));
        }
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to get thing: {}", e)})),
    };

    // Check ownership
    if thing.user_id != auth_user.user_id {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "Thing not found"}));
    }

    // Apply updates
    if let Some(ref t) = body.thing_type {
        thing.thing_type = t.clone();
    }
    if let Some(ref c) = body.content {
        thing.content = c.clone();
    }
    if let Some(ref m) = body.metadata {
        thing.metadata = m.clone();
    }
    if let Some(ref v) = body.visibility {
        thing.visibility = v.clone();
    }

    match state.store.update_thing(&mut thing) {
        Ok(_) => HttpResponse::Ok().json(thing), // Return plain object
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to update thing: {}", e)})),
    }
}

pub async fn delete_thing(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:delete") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: things:delete"}));
    }

    let id = path.into_inner();

    // Verify ownership first
    match state.store.get_thing(&id) {
        Ok(thing) => {
            if thing.user_id != auth_user.user_id {
                return HttpResponse::NotFound().json(serde_json::json!({"error": "Thing not found"}));
            }
        }
        Err(StoreError::NotFound(_)) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "Thing not found"}));
        }
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to get thing: {}", e)})),
    }

    match state.store.delete_thing(&id) {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to delete thing: {}", e)})),
    }
}

pub async fn get_thing_backlinks(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:read") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: things:read"}));
    }

    let id = path.into_inner();

    match state.store.get_backlinks(&auth_user.user_id, &id) {
        Ok(backlinks) => {
            // Return in same format as Go backend: { "backlinks": [...] }
            HttpResponse::Ok().json(serde_json::json!({
                "backlinks": backlinks
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to get backlinks: {}", e)})),
    }
}

// ==================== Photos Endpoints ====================

pub async fn get_photo(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let id = path.into_inner();
    match state.store.get_photo(&id) {
        Ok(photo) => {
            HttpResponse::Ok()
                .content_type(photo.content_type)
                .body(photo.data)
        }
        Err(StoreError::NotFound(_)) => HttpResponse::NotFound().finish(),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

/// Upload photos and create a gallery Thing
pub async fn upload_photo(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    mut payload: Multipart,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: things:write"}));
    }

    let mut files: Vec<(String, String, Vec<u8>, i64)> = Vec::new(); // (filename, content_type, data, size)
    let mut captions: Vec<String> = Vec::new();
    let mut content = String::new();
    let mut visibility = "private".to_string();

    // Parse multipart form
    while let Some(item) = payload.next().await {
        let mut field = match item {
            Ok(f) => f,
            Err(e) => {
                return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("Failed to parse form: {}", e)}));
            }
        };

        let content_disposition = match field.content_disposition() {
            Some(cd) => cd,
            None => continue,
        };
        let field_name = content_disposition.get_name().unwrap_or("");

        match field_name {
            "files" => {
                let filename = content_disposition
                    .get_filename()
                    .unwrap_or("unknown")
                    .to_string();
                let content_type = field
                    .content_type()
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "application/octet-stream".to_string());

                // Read file data
                let mut data = Vec::new();
                while let Some(chunk) = field.next().await {
                    match chunk {
                        Ok(bytes) => data.extend_from_slice(&bytes),
                        Err(e) => {
                            return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("Failed to read file: {}", e)}));
                        }
                    }
                }

                // Validate file type
                if !content_type.starts_with("image/") && !content_type.starts_with("video/") {
                    return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("Invalid file type: {}", content_type)}));
                }

                let size = data.len() as i64;
                files.push((filename, content_type, data, size));
            }
            "captions" => {
                let mut caption_data = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(bytes) = chunk {
                        caption_data.extend_from_slice(&bytes);
                    }
                }
                if let Ok(caption) = String::from_utf8(caption_data) {
                    captions.push(caption);
                }
            }
            "content" => {
                let mut content_data = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(bytes) = chunk {
                        content_data.extend_from_slice(&bytes);
                    }
                }
                if let Ok(c) = String::from_utf8(content_data) {
                    content = c;
                }
            }
            "visibility" => {
                let mut vis_data = Vec::new();
                while let Some(chunk) = field.next().await {
                    if let Ok(bytes) = chunk {
                        vis_data.extend_from_slice(&bytes);
                    }
                }
                if let Ok(v) = String::from_utf8(vis_data) {
                    visibility = v;
                }
            }
            _ => {
                // Skip unknown fields
                while field.next().await.is_some() {}
            }
        }
    }

    if files.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "No files provided"}));
    }

    // Create a gallery Thing
    let mut thing = Thing {
        id: String::new(),
        user_id: auth_user.user_id.clone(),
        thing_type: "gallery".to_string(),
        content,
        metadata: serde_json::from_str(&format!(r#"{{"photoCount": {}}}"#, files.len())).unwrap_or_default(),
        visibility,
        version: 0,
        deleted_at: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
        photos: Vec::new(),
    };

    if let Err(e) = state.store.create_thing(&mut thing) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to create gallery: {}", e)}));
    }

    // Create photos linked to the gallery
    let mut photos = Vec::new();
    for (i, (filename, content_type, data, size)) in files.into_iter().enumerate() {
        let caption = captions.get(i).cloned().unwrap_or_default();
        let mut photo = Photo {
            id: String::new(),
            thing_id: thing.id.clone(),
            caption,
            order_index: i as i32,
            data,
            content_type,
            filename,
            size,
            created_at: Utc::now(),
        };

        if let Err(e) = state.store.create_photo(&mut photo) {
            // Clean up: delete the thing if photo creation fails
            let _ = state.store.delete_thing(&thing.id);
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to save photo: {}", e)}));
        }
        photos.push(photo);
    }

    thing.photos = photos;

    HttpResponse::Created().json(thing)
}

// ==================== API Keys Endpoints ====================

#[derive(Deserialize)]
pub struct CreateApiKeyRequest {
    name: String,
    scopes: Vec<String>,
}

pub async fn list_api_keys(
    state: web::Data<AppState>,
    auth_user: AuthUser,
) -> impl Responder {
    if !has_scope(&auth_user, "keys:manage") && auth_user.is_api_key {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: keys:manage"}));
    }

    match state.store.list_api_keys(&auth_user.user_id) {
        // Return Go format: { keys: [...], availableScopes: [...] }
        Ok(keys) => HttpResponse::Ok().json(serde_json::json!({
            "keys": keys,
            "availableScopes": API_KEY_SCOPES
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to list API keys: {}", e)})),
    }
}

pub async fn create_api_key(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    body: web::Json<CreateApiKeyRequest>,
) -> impl Responder {
    if !has_scope(&auth_user, "keys:manage") && auth_user.is_api_key {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: keys:manage"}));
    }

    // Validate scopes
    for scope in &body.scopes {
        if !API_KEY_SCOPES.contains(&scope.as_str()) {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": format!("Invalid scope: {}", scope)}));
        }
    }

    let raw_key = AuthService::generate_api_key();
    let key_hash = match state.auth_service.hash_password(&raw_key) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": "Failed to hash key"})),
    };

    let mut api_key = ApiKey {
        id: String::new(),
        user_id: auth_user.user_id.clone(),
        name: body.name.clone(),
        key_hash,
        key_prefix: AuthService::get_api_key_prefix(&raw_key),
        scopes: body.scopes.clone(),
        metadata: None,
        last_used_at: None,
        expires_at: None,
        created_at: Utc::now(),
    };

    match state.store.create_api_key(&mut api_key) {
        Ok(_) => {
            // Return Go format: direct object with key shown once on creation
            HttpResponse::Created().json(serde_json::json!({
                "id": api_key.id,
                "name": api_key.name,
                "keyPrefix": api_key.key_prefix,
                "key": raw_key,
                "scopes": api_key.scopes,
                "createdAt": api_key.created_at
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to create API key: {}", e)})),
    }
}

pub async fn delete_api_key(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    if !has_scope(&auth_user, "keys:manage") && auth_user.is_api_key {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: keys:manage"}));
    }

    let id = path.into_inner();
    match state.store.delete_api_key(&id, &auth_user.user_id) {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(StoreError::NotFound(_)) => {
            HttpResponse::NotFound().json(serde_json::json!({"error": "API key not found"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to delete API key: {}", e)})),
    }
}

// ==================== Kinds Endpoints ====================

pub async fn list_kinds(
    state: web::Data<AppState>,
    auth_user: AuthUser,
) -> impl Responder {
    if !has_scope(&auth_user, "kinds:read") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: kinds:read"}));
    }

    match state.store.list_kinds(&auth_user.user_id) {
        Ok(kinds) => HttpResponse::Ok().json(kinds), // Return plain array like Go backend
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to list kinds: {}", e)})),
    }
}

pub async fn get_kind(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    if !has_scope(&auth_user, "kinds:read") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: kinds:read"}));
    }

    let id = path.into_inner();
    match state.store.get_kind(&id) {
        Ok(kind) => {
            if kind.user_id != auth_user.user_id {
                return HttpResponse::NotFound().json(serde_json::json!({"error": "Kind not found"}));
            }
            HttpResponse::Ok().json(kind) // Return plain object
        }
        Err(StoreError::NotFound(_)) => {
            HttpResponse::NotFound().json(serde_json::json!({"error": "Kind not found"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to get kind: {}", e)})),
    }
}

pub async fn create_kind(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    body: web::Json<CreateKindRequest>,
) -> impl Responder {
    if !has_scope(&auth_user, "kinds:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: kinds:write"}));
    }

    let mut kind = Kind {
        id: String::new(),
        user_id: auth_user.user_id.clone(),
        name: body.name.clone(),
        icon: body.icon.clone(),
        template: body.template.clone(),
        attributes: body.attributes.clone(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    match state.store.create_kind(&mut kind) {
        Ok(_) => HttpResponse::Created().json(kind), // Return plain object like Go backend
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to create kind: {}", e)})),
    }
}

pub async fn update_kind(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
    body: web::Json<UpdateKindRequest>,
) -> impl Responder {
    if !has_scope(&auth_user, "kinds:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: kinds:write"}));
    }

    let id = path.into_inner();
    let mut kind = match state.store.get_kind(&id) {
        Ok(k) => k,
        Err(StoreError::NotFound(_)) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "Kind not found"}));
        }
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to get kind: {}", e)})),
    };

    if kind.user_id != auth_user.user_id {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "Kind not found"}));
    }

    if let Some(ref n) = body.name {
        kind.name = n.clone();
    }
    if let Some(ref i) = body.icon {
        kind.icon = i.clone();
    }
    if let Some(ref t) = body.template {
        kind.template = t.clone();
    }
    if let Some(ref a) = body.attributes {
        kind.attributes = a.clone();
    }

    match state.store.update_kind(&mut kind) {
        Ok(_) => HttpResponse::Ok().json(kind), // Return plain object
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to update kind: {}", e)})),
    }
}

pub async fn delete_kind(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    if !has_scope(&auth_user, "kinds:delete") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: kinds:delete"}));
    }

    let id = path.into_inner();

    // Verify ownership
    match state.store.get_kind(&id) {
        Ok(kind) => {
            if kind.user_id != auth_user.user_id {
                return HttpResponse::NotFound().json(serde_json::json!({"error": "Kind not found"}));
            }
        }
        Err(StoreError::NotFound(_)) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "Kind not found"}));
        }
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to get kind: {}", e)})),
    }

    match state.store.delete_kind(&id) {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to delete kind: {}", e)})),
    }
}

// ==================== Frontend Serving ====================

/// Serve the frontend index.html for SPA routing
pub async fn serve_frontend() -> impl Responder {
    // Try to load frontend from cmd/tenant/dist directory
    let frontend_paths = vec![
        "cmd/tenant/dist/index.html",
        "../cmd/tenant/dist/index.html",
        "../../cmd/tenant/dist/index.html",
        "./dist/index.html",
    ];

    for path in frontend_paths {
        if let Ok(content) = std::fs::read_to_string(path) {
            return HttpResponse::Ok()
                .content_type("text/html; charset=utf-8")
                .body(content);
        }
    }

    // Fallback if no frontend found
    HttpResponse::NotFound().body("Frontend not found")
}

/// Serve static assets from dist/assets
pub async fn serve_assets(req: HttpRequest) -> impl Responder {
    let path = req.path();

    let asset_paths = vec![
        format!("cmd/tenant/dist{}", path),
        format!("../cmd/tenant/dist{}", path),
        format!("../../cmd/tenant/dist{}", path),
        format!("./dist{}", path),
    ];

    for asset_path in asset_paths {
        if let Ok(content) = std::fs::read(&asset_path) {
            let content_type = if path.ends_with(".js") {
                "application/javascript"
            } else if path.ends_with(".css") {
                "text/css"
            } else if path.ends_with(".svg") {
                "image/svg+xml"
            } else if path.ends_with(".png") {
                "image/png"
            } else if path.ends_with(".jpg") || path.ends_with(".jpeg") {
                "image/jpeg"
            } else if path.ends_with(".woff2") {
                "font/woff2"
            } else {
                "application/octet-stream"
            };

            return HttpResponse::Ok()
                .content_type(content_type)
                .body(content);
        }
    }

    HttpResponse::NotFound().body("Asset not found")
}

// ==================== Follow Endpoints ====================

/// POST /api/follows/create-token - Create an ephemeral follow verification token
/// Returns a token that can be used to verify follow requests across instances
pub async fn create_follow_token(
    state: web::Data<AppState>,
    auth_user: AuthUser,
) -> impl Responder {
    // Get the instance endpoint from environment or config
    // For now, we'll construct it from a config or use a default
    let endpoint = std::env::var("INSTANCE_URL")
        .unwrap_or_else(|_| "http://localhost:7777".to_string());

    match state.store.create_follow_token(&auth_user.user_id, &endpoint) {
        Ok(token) => {
            let response = crate::models::CreateFollowTokenResponse {
                follow_token: token,
                expires_in: 300,  // 5 minutes
            };
            HttpResponse::Ok().json(ApiResponse::success(response))
        }
        Err(_) => {
            HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Failed to create follow token"))
        }
    }
}

/// POST /api/friends - Add a friend (federated following)
/// Accepts remote_endpoint and access_token for cross-node connections
pub async fn add_friend(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    req: web::Json<crate::models::AddFriendRequest>,
) -> impl Responder {
    let remote_user_id = &req.remote_user_id;
    let remote_endpoint = &req.remote_endpoint;
    let access_token = req.access_token.clone();

    // Check if already following
    match state.store.is_following(&auth_user.user_id, remote_user_id) {
        Ok(true) => {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error("Already following this user"));
        }
        Ok(false) => {}
        Err(_) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error"));
        }
    }

    // Create friend relationship
    let mut follow = crate::models::Follow {
        id: String::new(),
        follower_id: auth_user.user_id.clone(),
        following_id: remote_user_id.clone(),
        remote_endpoint: remote_endpoint.clone(),
        access_token,
        created_at: Utc::now(),
        last_confirmed_at: None,
    };

    match state.store.create_follow(&mut follow) {
        Ok(_) => {
            // Emit follow.created event for subscriptions to process
            let event = crate::events::follow_created_event(
                &auth_user.user_id,
                remote_user_id,
                &follow.id,
            );

            // Process event asynchronously (fire-and-forget)
            // Event processing happens in the background
            let processor = state.event_processor.clone();
            tokio::spawn(async move {
                if let Err(e) = processor.process(&event).await {
                    log::warn!("Failed to process follow.created event: {:?}", e);
                }
            });

            HttpResponse::Created().json(ApiResponse::success(follow))
        }
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to add friend")),
    }
}

/// DELETE /api/follows/{user_id} - Unfollow a user
pub async fn unfollow_user(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    let following_id = path.into_inner();

    match state.store.delete_follow(&auth_user.user_id, &following_id) {
        Ok(_) => HttpResponse::Ok().json(ApiResponse::<()>::success(())),
        Err(StoreError::NotFound(_)) => {
            HttpResponse::NotFound().json(ApiResponse::<()>::error("Not following this user"))
        }
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

/// GET /api/follows/followers - Get list of followers (full records)
pub async fn get_followers(
    state: web::Data<AppState>,
    auth_user: AuthUser,
) -> impl Responder {
    match state.store.get_follower_records(&auth_user.user_id) {
        Ok(followers) => HttpResponse::Ok().json(ApiResponse::success(followers)),
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

/// GET /api/follows/following - Get list of users being followed (full records)
pub async fn get_following(
    state: web::Data<AppState>,
    auth_user: AuthUser,
) -> impl Responder {
    match state.store.get_following_records(&auth_user.user_id) {
        Ok(following) => HttpResponse::Ok().json(ApiResponse::success(following)),
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

/// GET /api/follows/mutuals - Get list of mutual followers (full records)
pub async fn get_mutuals(
    state: web::Data<AppState>,
    auth_user: AuthUser,
) -> impl Responder {
    match state.store.get_mutuals_records(&auth_user.user_id) {
        Ok(mutuals) => HttpResponse::Ok().json(ApiResponse::success(mutuals)),
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

/// GET /api/public/follows/{user_id} - Check if this instance's owner follows a user
/// Used for federated mutual detection - no auth required
pub async fn check_follows_user(
    state: web::Data<AppState>,
    path: web::Path<String>,
) -> impl Responder {
    let target_user_id = path.into_inner();

    // Get the owner of this instance (first/only user in single-tenant mode)
    let owner = match state.store.get_first_user() {
        Ok(Some(user)) => user,
        _ => return HttpResponse::NotFound().json(ApiResponse::<bool>::error("No owner found")),
    };

    // Check if owner follows the target user
    match state.store.is_following(&owner.id, &target_user_id) {
        Ok(follows) => HttpResponse::Ok().json(ApiResponse::success(follows)),
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<bool>::error("Database error")),
    }
}

/// POST /api/fed/notify-follow - Receive a follow notification from a remote instance
/// Remote instances call this to notify that one of their users is following us
/// This initiates the token verification handshake
pub async fn notify_follow(
    state: web::Data<AppState>,
    req: web::Json<crate::models::NotifyFollowRequest>,
) -> impl Responder {
    let follower_user_id = &req.follower_user_id;
    let follower_endpoint = &req.follower_endpoint;
    let follow_token = &req.follow_token;

    // Input validation
    if follower_user_id.is_empty() {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("follower_user_id cannot be empty"));
    }
    if follower_endpoint.is_empty() {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("follower_endpoint cannot be empty"));
    }
    if follow_token.is_empty() {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("follow_token cannot be empty"));
    }

    // Prevent extremely long inputs (resource exhaustion)
    if follower_user_id.len() > 255 || follower_endpoint.len() > 2048 || follow_token.len() > 1024 {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Request fields exceed maximum length"));
    }

    // Validate endpoint format (basic check: must start with http:// or https://)
    if !follower_endpoint.starts_with("http://") && !follower_endpoint.starts_with("https://") {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Invalid endpoint format - must be http:// or https://"));
    }

    // Security check: Prevent following your own instance
    let current_endpoint = std::env::var("INSTANCE_URL")
        .unwrap_or_else(|_| "http://localhost:7777".to_string());

    // Normalize both endpoints for comparison (remove trailing slashes)
    let follower_endpoint_normalized = follower_endpoint.trim_end_matches('/');
    let current_endpoint_normalized = current_endpoint.trim_end_matches('/');

    if follower_endpoint_normalized == current_endpoint_normalized {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Cannot follow your own instance"));
    }

    // Step 1: Verify the token by calling back to the follower's instance
    let verify_url = format!("{}/api/fed/verify-follow", follower_endpoint);

    let verify_req = crate::models::FollowVerifyRequest {
        follow_token: follow_token.clone(),
    };

    // Make HTTP request to verify token
    let client = reqwest::Client::new();
    let verify_result = client
        .post(&verify_url)
        .json(&verify_req)
        .send()
        .await;

    let is_valid = match verify_result {
        Ok(response) => {
            // Try to parse response
            match response.json::<ApiResponse<crate::models::FollowVerifyResponse>>().await {
                Ok(api_resp) => {
                    if let Some(data) = api_resp.data {
                        data.valid
                    } else {
                        false
                    }
                }
                Err(_) => false,
            }
        }
        Err(_) => false,
    };

    if !is_valid {
        return HttpResponse::BadRequest()
            .json(ApiResponse::<()>::error("Token verification failed"));
    }

    // Step 2: Token is valid, record the follower
    let owner = match state.store.get_first_user() {
        Ok(Some(user)) => user,
        _ => {
            return HttpResponse::InternalServerError()
                .json(ApiResponse::<()>::error("Could not find instance owner"))
        }
    };

    // Record the follower (creates or updates the follow record)
    if let Err(e) = state.store.record_follower(follower_user_id, follower_endpoint, &owner.id) {
        log::warn!("Failed to record follower: {:?}", e);
        return HttpResponse::InternalServerError()
            .json(ApiResponse::<()>::error("Failed to record follow"));
    }

    // Step 3: Return success
    HttpResponse::Ok().json(ApiResponse::success(()))
}

/// POST /api/fed/verify-follow - Verify a follow token for federated follow handshake
/// Called by remote instances to verify that a follow request is legitimate
/// No auth required - verification is done via token validation
pub async fn verify_follow(
    state: web::Data<AppState>,
    req: web::Json<crate::models::FollowVerifyRequest>,
) -> impl Responder {
    // Input validation
    if req.follow_token.is_empty() || req.follow_token.len() > 1024 {
        let response = crate::models::FollowVerifyResponse {
            valid: false,
            user_id: None,
            endpoint: None,
        };
        return HttpResponse::Ok().json(ApiResponse::success(response));
    }

    let (valid, user_id, endpoint) = state.store.verify_follow_token(&req.follow_token);

    let response = crate::models::FollowVerifyResponse {
        valid,
        user_id,
        endpoint,
    };

    // Always return 200 to avoid leaking token validity via HTTP status codes
    HttpResponse::Ok().json(ApiResponse::success(response))
}

/// GET /api/fed/things/{user_id} - Fetch friend-visible content from this node
/// CRITICAL: Only returns PUBLIC and FRIENDS visibility - NEVER private
/// This endpoint is called by remote friend nodes to fetch content
///
/// Optional query params for passive follow confirmation:
/// - requester_id: The user ID of the requester (who is following us)
/// - requester_endpoint: The endpoint of the requester's instance
/// When provided, updates last_confirmed_at to track active followers
pub async fn get_friend_visible_things(
    state: web::Data<AppState>,
    path: web::Path<String>,
    query: web::Query<HashMap<String, String>>,
) -> impl Responder {
    let user_id = path.into_inner();
    let limit: i64 = query.get("limit").and_then(|s| s.parse().ok()).unwrap_or(50);
    let offset: i64 = query.get("offset").and_then(|s| s.parse().ok()).unwrap_or(0);

    // Passive follow confirmation: if requester info provided, record/update the follower
    // This piggybacks on feed fetches - no separate heartbeat needed
    if let (Some(requester_id), Some(requester_endpoint)) = (
        query.get("requester_id"),
        query.get("requester_endpoint"),
    ) {
        // Get the owner of this instance to record them as the "following" target
        if let Ok(Some(owner)) = state.store.get_first_user() {
            // Record that requester_id (from requester_endpoint) follows owner
            // This updates last_confirmed_at if exists, or creates new record
            if let Err(e) = state.store.record_follower(requester_id, requester_endpoint, &owner.id) {
                log::warn!("Failed to record follower confirmation: {:?}", e);
            }
        }
    }

    // Get all things for this user (None = all types)
    match state.store.list_things(&user_id, None, limit, offset) {
        Ok(things) => {
            // CRITICAL SECURITY: Filter to ONLY public and friends visibility
            let friend_visible: Vec<_> = things
                .into_iter()
                .filter(|thing| thing.visibility == "public" || thing.visibility == "friends")
                .collect();

            HttpResponse::Ok().json(ApiResponse::success(friend_visible))
        }
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

/// GET /api/feed/friends - Get friend feed (posts from followed users)
pub async fn get_friend_feed(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    query: web::Query<PaginationQuery>,
) -> impl Responder {
    let limit = query.limit.unwrap_or(50) as i64;
    let offset = query.offset.unwrap_or(0) as i64;

    match state.store.get_friend_feed(&auth_user.user_id, limit, offset) {
        Ok(things) => HttpResponse::Ok().json(things),
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

// ==================== Notification Endpoints ====================

/// GET /api/notifications - List notifications for current user
pub async fn list_notifications(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    query: web::Query<PaginationQuery>,
) -> impl Responder {
    let limit = query.limit.unwrap_or(50) as i64;
    let offset = query.offset.unwrap_or(0) as i64;

    match state.store.list_notifications(&auth_user.user_id, limit, offset) {
        Ok(notifications) => {
            let total = state.store.count_notifications(&auth_user.user_id).unwrap_or(0);
            let unread = state.store.get_unread_count(&auth_user.user_id).unwrap_or(0);

            HttpResponse::Ok().json(serde_json::json!({
                "success": true,
                "data": {
                    "notifications": notifications,
                    "total": total,
                    "unread": unread,
                    "limit": limit,
                    "offset": offset
                }
            }))
        }
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

/// GET /api/notifications/unread-count - Get count of unread notifications
pub async fn get_unread_count(
    state: web::Data<AppState>,
    auth_user: AuthUser,
) -> impl Responder {
    match state.store.get_unread_count(&auth_user.user_id) {
        Ok(count) => HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({ "count": count }))),
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

/// PUT /api/notifications/read-all - Mark all notifications as read
pub async fn mark_all_read(
    state: web::Data<AppState>,
    auth_user: AuthUser,
) -> impl Responder {
    match state.store.mark_all_notifications_read(&auth_user.user_id) {
        Ok(count) => HttpResponse::Ok().json(ApiResponse::success(serde_json::json!({ "marked_read": count }))),
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

/// PUT /api/notifications/{id}/read - Mark single notification as read
pub async fn mark_notification_read(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    let notification_id = path.into_inner();

    match state.store.mark_notification_read(&notification_id, &auth_user.user_id) {
        Ok(_) => HttpResponse::Ok().json(ApiResponse::<()>::success(())),
        Err(StoreError::NotFound(_)) => {
            HttpResponse::NotFound().json(ApiResponse::<()>::error("Notification not found"))
        }
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

/// DELETE /api/notifications/{id} - Delete a notification
pub async fn delete_notification(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    let notification_id = path.into_inner();

    match state.store.delete_notification(&notification_id, &auth_user.user_id) {
        Ok(_) => HttpResponse::Ok().json(ApiResponse::<()>::success(())),
        Err(StoreError::NotFound(_)) => {
            HttpResponse::NotFound().json(ApiResponse::<()>::error("Notification not found"))
        }
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

/// GET /api/notifications/settings - Get notification settings
pub async fn get_notification_settings(
    state: web::Data<AppState>,
    auth_user: AuthUser,
) -> impl Responder {
    match state.store.get_all_notification_settings(&auth_user.user_id) {
        Ok(settings) => HttpResponse::Ok().json(ApiResponse::success(settings)),
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

/// PUT /api/notifications/settings - Update notification settings
pub async fn update_notification_settings(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    body: web::Json<crate::models::UpdateNotificationSettingsRequest>,
) -> impl Responder {
    match state.store.update_notification_settings(
        &auth_user.user_id,
        &body.notification_type,
        body.enabled,
    ) {
        Ok(settings) => HttpResponse::Ok().json(ApiResponse::success(settings)),
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

/// POST /api/notifications/inbound - Receive notification from remote node
/// This is called by other nodes trying to send notifications to this user.
/// Responds with "accepted" or "rejected" based on user's settings.
pub async fn receive_inbound_notification(
    state: web::Data<AppState>,
    body: web::Json<crate::models::InboundNotificationRequest>,
) -> impl Responder {
    // For now, we need to determine the target user from the request URL or auth
    // In a production system, this would use the server owner's ID
    // For simplicity, we'll accept notifications for the server owner
    let owner = match state.store.get_user_by_username(&std::env::var("OWNER_USERNAME").unwrap_or_else(|_| "owner".to_string())) {
        Ok(user) => user,
        Err(_) => {
            return HttpResponse::InternalServerError().json(crate::models::InboundNotificationResponse {
                status: "error".to_string(),
            });
        }
    };

    // Check if user accepts this notification type
    let accepted = match state.store.get_notification_settings(&owner.id, &body.notification_type) {
        Ok(settings) => settings.enabled,
        Err(_) => true, // Default to accepting if no settings exist
    };

    if !accepted {
        return HttpResponse::Ok().json(crate::models::InboundNotificationResponse {
            status: "rejected".to_string(),
        });
    }

    // Create the notification
    let notification = crate::models::Notification {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: owner.id.clone(),
        notification_type: body.notification_type.clone(),
        actor_id: body.actor_id.clone(),
        actor_type: body.actor_type.clone(),
        resource_type: body.resource_type.clone(),
        resource_id: body.resource_id.clone(),
        title: body.title.clone(),
        body: body.body.clone(),
        url: body.url.clone(),
        metadata: body.metadata.clone(),
        read: false,
        created_at: Utc::now(),
    };

    match state.store.create_notification(&notification) {
        Ok(_) => HttpResponse::Ok().json(crate::models::InboundNotificationResponse {
            status: "accepted".to_string(),
        }),
        Err(_) => HttpResponse::InternalServerError().json(crate::models::InboundNotificationResponse {
            status: "error".to_string(),
        }),
    }
}

// ==================== Reaction Endpoints ====================

/// POST /api/things/{id}/reactions - Add a reaction to a thing
pub async fn add_reaction(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
    body: web::Json<crate::models::AddReactionRequest>,
) -> impl Responder {
    let thing_id = path.into_inner();

    // Validate reaction type
    if !crate::models::ALLOWED_REACTIONS.contains(&body.reaction_type.as_str()) {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(
            format!("Invalid reaction type. Allowed: {:?}", crate::models::ALLOWED_REACTIONS)
        ));
    }

    // Check thing exists and user has access
    match state.store.get_thing(&thing_id) {
        Ok(_thing) => {}
        Err(StoreError::NotFound(_)) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error("Thing not found"));
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error"));
        }
    }

    let reaction = crate::models::Reaction {
        id: uuid::Uuid::new_v4().to_string(),
        user_id: auth_user.user_id.clone(),
        thing_id: thing_id.clone(),
        reaction_type: body.reaction_type.clone(),
        created_at: Utc::now(),
    };

    match state.store.add_reaction(&reaction) {
        Ok(_) => {
            // Get updated summary
            match state.store.get_reaction_summary(&thing_id, Some(&auth_user.user_id)) {
                Ok(summary) => HttpResponse::Created().json(ApiResponse::success(summary)),
                Err(_) => HttpResponse::Created().json(ApiResponse::<()>::success(())),
            }
        }
        Err(crate::store::StoreError::Database(e)) if e.to_string().contains("UNIQUE") => {
            HttpResponse::Conflict().json(ApiResponse::<()>::error("Already reacted with this type"))
        }
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

/// DELETE /api/things/{thing_id}/reactions/{reaction_type} - Remove a reaction
pub async fn remove_reaction(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<(String, String)>,
) -> impl Responder {
    let (thing_id, reaction_type) = path.into_inner();

    match state.store.remove_reaction(&auth_user.user_id, &thing_id, &reaction_type) {
        Ok(_) => {
            match state.store.get_reaction_summary(&thing_id, Some(&auth_user.user_id)) {
                Ok(summary) => HttpResponse::Ok().json(ApiResponse::success(summary)),
                Err(_) => HttpResponse::Ok().json(ApiResponse::<()>::success(())),
            }
        }
        Err(StoreError::NotFound(_)) => {
            HttpResponse::NotFound().json(ApiResponse::<()>::error("Reaction not found"))
        }
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

/// GET /api/things/{id}/reactions - Get reactions for a thing
pub async fn get_reactions(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    let thing_id = path.into_inner();

    match state.store.get_reaction_summary(&thing_id, Some(&auth_user.user_id)) {
        Ok(summary) => HttpResponse::Ok().json(ApiResponse::success(summary)),
        Err(_) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error")),
    }
}

// ==================== STUB HANDLERS (TODO: Implement) ====================

// Auth stubs
async fn check_auth(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> impl Responder {
    // Check sandbox mode
    let owner_username = env::var("OWNER_USERNAME").unwrap_or_default();
    if owner_username == "sandbox" {
        match state.store.get_user_by_username("sandbox") {
            Ok(user) => {
                return HttpResponse::Ok().json(serde_json::json!({
                    "authenticated": true,
                    "user": user,
                    "sandboxMode": true
                }));
            }
            Err(_) => {
                return HttpResponse::Ok().json(serde_json::json!({"authenticated": false}));
            }
        }
    }

    // Extract token from Authorization header or cookie
    let token = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .map(|t| t.to_string())
        .or_else(|| req.cookie("tenant_auth").map(|c| c.value().to_string()));

    let token = match token {
        Some(t) if !t.is_empty() => t,
        _ => return HttpResponse::Ok().json(serde_json::json!({"authenticated": false})),
    };

    // Validate JWT token
    let claims = match state.auth_service.validate_token(&token) {
        Ok(c) => c,
        Err(_) => return HttpResponse::Ok().json(serde_json::json!({"authenticated": false})),
    };

    // Get user and check if locked
    match state.store.get_user(&claims.sub) {
        Ok(user) if !user.is_locked => {
            HttpResponse::Ok().json(serde_json::json!({
                "authenticated": true,
                "user": user
            }))
        }
        _ => HttpResponse::Ok().json(serde_json::json!({"authenticated": false})),
    }
}

async fn update_current_user(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    body: web::Json<UpdateProfileRequest>,
) -> impl Responder {
    // Get current user
    let mut user = match state.store.get_user(&auth_user.user_id) {
        Ok(u) => u,
        Err(_) => return HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
    };

    // Update profile fields
    if let Some(display_name) = &body.display_name {
        user.display_name = display_name.clone();
    }
    if let Some(bio) = &body.bio {
        user.bio = bio.clone();
    }
    if let Some(avatar_url) = &body.avatar_url {
        user.avatar_url = avatar_url.clone();
    }

    // Save changes
    if let Err(e) = state.store.update_user(&user) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to update profile: {}", e)}));
    }

    HttpResponse::Ok().json(user)
}

// API Key handlers
async fn get_api_key(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    if !has_scope(&auth_user, "keys:manage") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: keys:manage"}));
    }

    let id = path.into_inner();
    match state.store.get_api_key_for_user(&id, &auth_user.user_id) {
        Ok(mut key) => {
            key.key_hash = String::new(); // Never expose hash
            HttpResponse::Ok().json(key)
        }
        Err(_) => HttpResponse::NotFound().json(serde_json::json!({"error": "API key not found"})),
    }
}

async fn update_api_key(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
    body: web::Json<UpdateApiKeyRequest>,
) -> impl Responder {
    if !has_scope(&auth_user, "keys:manage") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Missing scope: keys:manage"}));
    }

    let id = path.into_inner();

    // Get existing key
    let mut key = match state.store.get_api_key_for_user(&id, &auth_user.user_id) {
        Ok(k) => k,
        Err(_) => return HttpResponse::NotFound().json(serde_json::json!({"error": "API key not found"})),
    };

    // Update fields
    if let Some(name) = &body.name {
        key.name = name.clone();
    }
    if let Some(scopes) = &body.scopes {
        key.scopes = scopes.clone();
    }
    if let Some(metadata) = &body.metadata {
        key.metadata = Some(metadata.clone());
    }
    if body.expires_at.is_some() {
        key.expires_at = body.expires_at;
    }

    // Save changes
    if let Err(e) = state.store.update_api_key(&key) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to update API key: {}", e)}));
    }

    key.key_hash = String::new(); // Never expose hash
    HttpResponse::Ok().json(key)
}

// Things stubs
async fn query_things(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:read") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    // Parse query parameters
    let thing_type = query.get("type").cloned();
    let sort = query.get("sort").cloned();
    let include_deleted = query.get("includeDeleted").map(|v| v == "true").unwrap_or(false);

    let page: i64 = query.get("page").and_then(|p| p.parse().ok()).unwrap_or(1);
    let count: i64 = match query.get("count") {
        Some(c) if c == "all" => -1,
        Some(c) => c.parse().unwrap_or(50),
        None => 50,
    };

    // Parse metadata filters (meta.field=value)
    let mut metadata_filter = std::collections::HashMap::new();
    for (key, value) in query.iter() {
        if key.starts_with("meta.") {
            let field = key.strip_prefix("meta.").unwrap().to_string();
            metadata_filter.insert(field, value.clone());
        }
    }

    let q = crate::store::ThingQuery {
        user_id: auth_user.user_id.clone(),
        thing_type,
        metadata_filter,
        sort,
        page,
        count,
        include_deleted,
    };

    match state.store.query_things(q) {
        Ok(result) => HttpResponse::Ok().json(result),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn search_things(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    query: web::Query<std::collections::HashMap<String, String>>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:read") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    let search_query = query.get("q").cloned().unwrap_or_default();
    let limit: i64 = query.get("limit").and_then(|l| l.parse().ok()).unwrap_or(50);

    match state.store.search_things(&auth_user.user_id, &search_query, limit) {
        Ok(things) => HttpResponse::Ok().json(things),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn list_thing_versions(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:read") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    let thing_id = path.into_inner();

    match state.store.list_thing_versions(&thing_id, &auth_user.user_id) {
        Ok(versions) => HttpResponse::Ok().json(versions),
        Err(crate::store::StoreError::NotFound(_)) => {
            HttpResponse::NotFound().json(serde_json::json!({"error": "Thing not found"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn get_thing_version(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<(String, i32)>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:read") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    let (thing_id, version) = path.into_inner();

    match state.store.get_thing_version(&thing_id, &auth_user.user_id, version) {
        Ok(v) => HttpResponse::Ok().json(v),
        Err(crate::store::StoreError::NotFound(_)) => {
            HttpResponse::NotFound().json(serde_json::json!({"error": "Version not found"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn revert_to_version(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<(String, i32)>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    let (thing_id, version) = path.into_inner();

    // Get the specified version
    let v = match state.store.get_thing_version(&thing_id, &auth_user.user_id, version) {
        Ok(v) => v,
        Err(crate::store::StoreError::NotFound(_)) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "Version not found"}));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
        }
    };

    // Get the current thing
    let mut thing = match state.store.get_thing(&thing_id) {
        Ok(t) => t,
        Err(_) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "Thing not found"}));
        }
    };

    // Update thing with version's content and metadata
    thing.content = v.content;
    thing.metadata = v.metadata;

    // Update the thing
    if let Err(e) = state.store.update_thing(&mut thing) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }

    HttpResponse::Ok().json(thing)
}

async fn upsert_thing(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    query: web::Query<std::collections::HashMap<String, String>>,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    // Validate required query params
    let thing_type = match query.get("type") {
        Some(t) if !t.is_empty() => t.clone(),
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "type query param is required"})),
    };

    let match_field = match query.get("matchField") {
        Some(f) if !f.is_empty() => f.clone(),
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "matchField query param is required"})),
    };

    let match_value = match query.get("matchValue") {
        Some(v) if !v.is_empty() => v.clone(),
        _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "matchValue query param is required"})),
    };

    // Parse the thing from body
    let content = body.get("content").and_then(|c| c.as_str()).unwrap_or("").to_string();
    let metadata = body.get("metadata")
        .and_then(|m| serde_json::from_value::<std::collections::HashMap<String, serde_json::Value>>(m.clone()).ok())
        .unwrap_or_default();

    let mut thing = crate::models::Thing {
        id: String::new(),
        user_id: auth_user.user_id.clone(),
        thing_type: thing_type.clone(),
        content,
        metadata,
        visibility: body.get("visibility").and_then(|v| v.as_str()).unwrap_or("private").to_string(),
        version: 1,
        deleted_at: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
        photos: vec![],
    };

    match state.store.upsert_thing(&auth_user.user_id, &thing_type, &match_field, &match_value, &mut thing) {
        Ok((result, created)) => {
            let status = if created {
                actix_web::http::StatusCode::CREATED
            } else {
                actix_web::http::StatusCode::OK
            };
            HttpResponse::build(status).json(serde_json::json!({
                "thing": result,
                "created": created,
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn bulk_create_things(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    // Parse request - expect {"things": [...]}
    let things_array = match body.get("things").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "No things provided"}));
        }
    };

    if things_array.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "No things provided"}));
    }

    if things_array.len() > 100 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Maximum 100 things per request"}));
    }

    // Parse things
    let mut things: Vec<crate::models::Thing> = Vec::with_capacity(things_array.len());
    for value in things_array {
        let thing_type = value.get("type").and_then(|v| v.as_str()).unwrap_or("note").to_string();
        let content = value.get("content").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let visibility = value.get("visibility").and_then(|v| v.as_str()).unwrap_or("private").to_string();
        let metadata: std::collections::HashMap<String, serde_json::Value> = value
            .get("metadata")
            .and_then(|v| serde_json::from_value(v.clone()).ok())
            .unwrap_or_default();

        things.push(crate::models::Thing {
            id: String::new(),
            user_id: auth_user.user_id.clone(),
            thing_type,
            content,
            metadata,
            visibility,
            version: 0,
            deleted_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            photos: Vec::new(),
        });
    }

    if let Err(e) = state.store.bulk_create_things(&mut things) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }

    HttpResponse::Created().json(serde_json::json!({
        "created": things.len(),
        "things": things
    }))
}

async fn bulk_update_things(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    let things_json = match body.get("things").and_then(|t| t.as_array()) {
        Some(t) => t,
        None => return HttpResponse::BadRequest().json(serde_json::json!({"error": "things array is required"})),
    };

    if things_json.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "No things provided"}));
    }

    if things_json.len() > 100 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Maximum 100 things per request"}));
    }

    // Parse things and validate all have IDs
    let mut things: Vec<crate::models::Thing> = Vec::new();
    for thing_json in things_json {
        let id = match thing_json.get("id").and_then(|i| i.as_str()) {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => return HttpResponse::BadRequest().json(serde_json::json!({"error": "All things must have an ID"})),
        };

        let thing_type = thing_json.get("type").and_then(|t| t.as_str()).unwrap_or("note").to_string();
        let content = thing_json.get("content").and_then(|c| c.as_str()).unwrap_or("").to_string();
        let metadata = thing_json.get("metadata")
            .and_then(|m| serde_json::from_value::<std::collections::HashMap<String, serde_json::Value>>(m.clone()).ok())
            .unwrap_or_default();
        let visibility = thing_json.get("visibility").and_then(|v| v.as_str()).unwrap_or("private").to_string();
        let version = thing_json.get("version").and_then(|v| v.as_i64()).unwrap_or(1) as i32;

        things.push(crate::models::Thing {
            id,
            user_id: auth_user.user_id.clone(),
            thing_type,
            content,
            metadata,
            visibility,
            version,
            deleted_at: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
            photos: vec![],
        });
    }

    match state.store.bulk_update_things(&auth_user.user_id, &mut things) {
        Ok(updated) => HttpResponse::Ok().json(serde_json::json!({
            "updated": updated,
            "things": things,
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn bulk_delete_things(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    // Parse request - expect {"ids": [...]}
    let ids_array = match body.get("ids").and_then(|v| v.as_array()) {
        Some(arr) => arr,
        None => {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "No IDs provided"}));
        }
    };

    if ids_array.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "No IDs provided"}));
    }

    if ids_array.len() > 100 {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Maximum 100 IDs per request"}));
    }

    let ids: Vec<String> = ids_array
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    if ids.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Invalid IDs format"}));
    }

    match state.store.bulk_delete_things(&auth_user.user_id, &ids) {
        Ok(deleted) => HttpResponse::Ok().json(serde_json::json!({
            "deleted": deleted
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn restore_thing(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    let thing_id = path.into_inner();

    // Restore the thing (sets deleted_at to NULL)
    if let Err(e) = state.store.restore_thing(&thing_id, &auth_user.user_id) {
        return match e {
            crate::store::StoreError::NotFound(_) => {
                HttpResponse::NotFound().json(serde_json::json!({"error": "Thing not found"}))
            }
            _ => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
        };
    }

    // Get the restored thing
    match state.store.get_thing(&thing_id) {
        Ok(thing) => HttpResponse::Ok().json(thing),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// Tags handlers
async fn list_tags(
    state: web::Data<AppState>,
    auth_user: AuthUser,
) -> impl Responder {
    if !has_scope(&auth_user, "things:read") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    match state.store.list_tags(&auth_user.user_id) {
        Ok(tags) => HttpResponse::Ok().json(tags),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn create_tag(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    // Parse name from body
    let name = match body.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n,
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "Name is required"}));
        }
    };

    match state.store.get_or_create_tag(&auth_user.user_id, name) {
        Ok(tag) => HttpResponse::Created().json(tag),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// Views handlers
async fn list_views(
    state: web::Data<AppState>,
    auth_user: AuthUser,
) -> impl Responder {
    if !has_scope(&auth_user, "things:read") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    match state.store.list_views(&auth_user.user_id) {
        Ok(views) => HttpResponse::Ok().json(views),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn create_view(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    // Parse name
    let name = match body.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => {
            return HttpResponse::BadRequest().json(serde_json::json!({"error": "Name is required"}));
        }
    };

    // Parse type with default
    let view_type = body.get("type").and_then(|v| v.as_str()).unwrap_or("feed").to_string();

    // Validate view type
    let valid_types = ["feed", "table", "board", "calendar"];
    if !valid_types.contains(&view_type.as_str()) {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid view type. Must be: feed, table, board, or calendar"
        }));
    }

    let kind_id = body.get("kindId").or(body.get("kind_id"))
        .and_then(|v| v.as_str())
        .map(String::from);

    let config: crate::models::ViewConfig = body
        .get("config")
        .and_then(|v| serde_json::from_value(v.clone()).ok())
        .unwrap_or_default();

    let mut view = crate::models::View {
        id: String::new(),
        user_id: auth_user.user_id.clone(),
        name,
        view_type,
        kind_id,
        config,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    };

    if let Err(e) = state.store.create_view(&mut view) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }

    HttpResponse::Created().json(view)
}

async fn get_view(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:read") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    let view_id = path.into_inner();

    match state.store.get_view(&view_id, &auth_user.user_id) {
        Ok(view) => HttpResponse::Ok().json(view),
        Err(crate::store::StoreError::NotFound(_)) => {
            HttpResponse::NotFound().json(serde_json::json!({"error": "View not found"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

async fn update_view(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    let view_id = path.into_inner();

    // Get existing view
    let mut view = match state.store.get_view(&view_id, &auth_user.user_id) {
        Ok(v) => v,
        Err(crate::store::StoreError::NotFound(_)) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "View not found"}));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
        }
    };

    // Update fields if provided
    if let Some(name) = body.get("name").and_then(|v| v.as_str()) {
        view.name = name.to_string();
    }

    if let Some(view_type) = body.get("type").and_then(|v| v.as_str()) {
        let valid_types = ["feed", "table", "board", "calendar"];
        if !valid_types.contains(&view_type) {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid view type. Must be: feed, table, board, or calendar"
            }));
        }
        view.view_type = view_type.to_string();
    }

    if let Some(kind_id) = body.get("kindId").or(body.get("kind_id")).and_then(|v| v.as_str()) {
        view.kind_id = Some(kind_id.to_string());
    }

    if let Some(config) = body.get("config") {
        if let Ok(c) = serde_json::from_value(config.clone()) {
            view.config = c;
        }
    }

    if let Err(e) = state.store.update_view(&mut view) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }

    HttpResponse::Ok().json(view)
}

async fn delete_view(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    let view_id = path.into_inner();

    match state.store.delete_view(&view_id, &auth_user.user_id) {
        Ok(()) => HttpResponse::NoContent().finish(),
        Err(crate::store::StoreError::NotFound(_)) => {
            HttpResponse::NotFound().json(serde_json::json!({"error": "View not found"}))
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()})),
    }
}

// Photos handlers
async fn update_photo(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    let photo_id = path.into_inner();

    // Get the photo to find its parent thing
    let photo = match state.store.get_photo(&photo_id) {
        Ok(p) => p,
        Err(crate::store::StoreError::NotFound(_)) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "Photo not found"}));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
        }
    };

    // Verify user owns the parent thing
    let thing = match state.store.get_thing(&photo.thing_id) {
        Ok(t) => t,
        Err(_) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "Parent thing not found"}));
        }
    };

    if thing.user_id != auth_user.user_id {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Not authorized to edit this photo"}));
    }

    // Parse caption from body
    let caption = body.get("caption")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    // Update the photo caption
    if let Err(e) = state.store.update_photo_caption(&photo_id, caption) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }

    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}

async fn delete_photo(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    let photo_id = path.into_inner();

    // Get the photo to find its parent thing
    let photo = match state.store.get_photo(&photo_id) {
        Ok(p) => p,
        Err(crate::store::StoreError::NotFound(_)) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "Photo not found"}));
        }
        Err(e) => {
            return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
        }
    };

    // Verify user owns the parent thing
    let thing = match state.store.get_thing(&photo.thing_id) {
        Ok(t) => t,
        Err(_) => {
            return HttpResponse::NotFound().json(serde_json::json!({"error": "Parent thing not found"}));
        }
    };

    if thing.user_id != auth_user.user_id {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Not authorized to delete this photo"}));
    }

    // Delete the photo
    if let Err(e) = state.store.delete_photo(&photo_id) {
        return HttpResponse::InternalServerError().json(serde_json::json!({"error": e.to_string()}));
    }

    HttpResponse::Ok().json(serde_json::json!({"status": "ok"}))
}

// Export/Import stubs
async fn export_data(
    state: web::Data<AppState>,
    auth_user: AuthUser,
) -> impl Responder {
    if !has_scope(&auth_user, "things:read") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    // Get all things for this user using query_things with count=-1 (all items)
    let query = crate::store::ThingQuery {
        user_id: auth_user.user_id.clone(),
        count: -1,
        include_deleted: false,
        ..Default::default()
    };

    let things = match state.store.query_things(query) {
        Ok(result) => result.things,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to export things: {}", e)
        })),
    };

    // Get all kinds for this user
    let kinds = match state.store.list_kinds(&auth_user.user_id) {
        Ok(k) => k,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to export kinds: {}", e)
        })),
    };

    let export = serde_json::json!({
        "version": "1.0",
        "exportedAt": chrono::Utc::now().to_rfc3339(),
        "things": things,
        "kinds": kinds,
    });

    // Set headers for file download
    let filename = format!("tenant-export-{}.json", chrono::Utc::now().format("%Y-%m-%d"));

    HttpResponse::Ok()
        .insert_header(("Content-Type", "application/json"))
        .insert_header(("Content-Disposition", format!("attachment; filename={}", filename)))
        .json(export)
}

async fn import_data(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    body: web::Json<serde_json::Value>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Insufficient permissions"}));
    }

    // Validate version
    let version = body.get("version").and_then(|v| v.as_str());
    if version.is_none() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Missing version field in import data"
        }));
    }

    // Get existing kinds to check for duplicates
    let existing_kinds = match state.store.list_kinds(&auth_user.user_id) {
        Ok(k) => k,
        Err(e) => return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to list existing kinds: {}", e)
        })),
    };
    let existing_kind_names: std::collections::HashSet<String> = existing_kinds.iter().map(|k| k.name.clone()).collect();

    // Import kinds first
    let mut kinds_created = 0;
    let mut kinds_skipped = 0;

    if let Some(kinds) = body.get("kinds").and_then(|k| k.as_array()) {
        for kind_json in kinds {
            let name = kind_json.get("name").and_then(|n| n.as_str()).unwrap_or("");
            if name.is_empty() || existing_kind_names.contains(name) {
                kinds_skipped += 1;
                continue;
            }

            // Parse attributes
            let attributes: Vec<crate::models::Attribute> = kind_json.get("attributes")
                .and_then(|a| serde_json::from_value(a.clone()).ok())
                .unwrap_or_default();

            let mut kind = crate::models::Kind {
                id: uuid::Uuid::new_v4().to_string(),
                user_id: auth_user.user_id.clone(),
                name: name.to_string(),
                icon: kind_json.get("icon").and_then(|i| i.as_str()).unwrap_or("").to_string(),
                template: kind_json.get("template").and_then(|t| t.as_str()).unwrap_or("").to_string(),
                attributes,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
            };

            if state.store.create_kind(&mut kind).is_ok() {
                kinds_created += 1;
            } else {
                kinds_skipped += 1;
            }
        }
    }

    // Import things
    let mut things_created = 0;
    let mut things_skipped = 0;

    if let Some(things) = body.get("things").and_then(|t| t.as_array()) {
        for thing_json in things {
            let thing_type = thing_json.get("type").and_then(|t| t.as_str()).unwrap_or("note");
            let content = thing_json.get("content").and_then(|c| c.as_str()).unwrap_or("");

            let metadata = thing_json.get("metadata")
                .and_then(|m| serde_json::from_value::<std::collections::HashMap<String, serde_json::Value>>(m.clone()).ok())
                .unwrap_or_default();

            let mut thing = crate::models::Thing {
                id: uuid::Uuid::new_v4().to_string(),
                user_id: auth_user.user_id.clone(),
                thing_type: thing_type.to_string(),
                content: content.to_string(),
                metadata,
                visibility: "private".to_string(),
                version: 1,
                deleted_at: None,
                created_at: chrono::Utc::now(),
                updated_at: chrono::Utc::now(),
                photos: vec![],
            };

            if state.store.create_thing(&mut thing).is_ok() {
                things_created += 1;
            } else {
                things_skipped += 1;
            }
        }
    }

    HttpResponse::Ok().json(serde_json::json!({
        "message": "Import completed",
        "kindsCreated": kinds_created,
        "kindsSkipped": kinds_skipped,
        "thingsCreated": things_created,
        "thingsSkipped": things_skipped,
    }))
}

// Admin handlers
async fn list_users(
    state: web::Data<AppState>,
    auth_user: AuthUser,
) -> impl Responder {
    // Check admin permission
    if !has_scope(&auth_user, "admin:*") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Admin access required"}));
    }

    match state.store.list_users() {
        Ok(users) => {
            // Clear sensitive fields
            let users: Vec<serde_json::Value> = users.iter().map(|u| {
                serde_json::json!({
                    "id": u.id,
                    "username": u.username,
                    "email": u.email,
                    "display_name": u.display_name,
                    "bio": u.bio,
                    "avatar_url": u.avatar_url,
                    "is_admin": u.is_admin,
                    "is_locked": u.is_locked,
                    "created_at": u.created_at,
                    "updated_at": u.updated_at
                })
            }).collect();
            HttpResponse::Ok().json(users)
        }
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("{}", e)})),
    }
}

async fn lock_user(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    // Check admin permission
    if !has_scope(&auth_user, "admin:*") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Admin access required"}));
    }

    let id = path.into_inner();

    // Can't lock yourself
    if id == auth_user.user_id {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Cannot lock yourself"}));
    }

    // Verify user exists
    if state.store.get_user(&id).is_err() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"}));
    }

    match state.store.lock_user(&id) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "ok"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to lock user: {}", e)})),
    }
}

async fn unlock_user(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    // Check admin permission
    if !has_scope(&auth_user, "admin:*") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Admin access required"}));
    }

    let id = path.into_inner();

    // Verify user exists
    if state.store.get_user(&id).is_err() {
        return HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"}));
    }

    match state.store.unlock_user(&id) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "ok"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to unlock user: {}", e)})),
    }
}

async fn delete_user(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    // Check admin permission
    if !has_scope(&auth_user, "admin:*") {
        return HttpResponse::Forbidden().json(serde_json::json!({"error": "Admin access required"}));
    }

    let id = path.into_inner();

    // Can't delete yourself
    if id == auth_user.user_id {
        return HttpResponse::BadRequest().json(serde_json::json!({"error": "Cannot delete yourself"}));
    }

    match state.store.delete_user(&id) {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({"status": "ok"})),
        Err(StoreError::NotFound(_)) => HttpResponse::NotFound().json(serde_json::json!({"error": "User not found"})),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({"error": format!("Failed to delete user: {}", e)})),
    }
}

// ==================== Route Configuration ====================

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg
        // Health check
        .route("/health", web::get().to(health))

        // Metrics endpoints
        .route("/api/metrics", web::get().to(crate::metrics::get_metrics_handler))
        .route("/api/metrics/time-series", web::get().to(crate::metrics::get_time_series_handler))
        .route("/api/metrics/uptime", web::get().to(crate::metrics::get_uptime_history_handler))
        .route("/api/metrics/status-breakdown", web::get().to(crate::metrics::get_status_breakdown_handler))
        .route("/api/metrics/cold-start", web::get().to(crate::metrics::get_cold_start_handler))
        .route("/api/metrics/reset", web::post().to(crate::metrics::reset_metrics_handler))
        .route("/api/metrics/cleanup", web::post().to(crate::metrics::cleanup_old_metrics_handler))

        // Auth routes (no auth required)
        .route("/api/auth/status", web::get().to(auth_status))
        .route("/api/auth/register", web::post().to(register))
        .route("/api/auth/login", web::post().to(login))
        .route("/api/auth/logout", web::post().to(logout))
        .route("/api/auth/check", web::get().to(check_auth))  // STUB

        // Public routes (no auth required)
        .route("/api/public/profile", web::get().to(get_public_profile))
        .route("/api/public/things", web::get().to(get_public_things))
        .route("/api/public/follows/{user_id}", web::get().to(check_follows_user))

        // Protected routes - will need auth middleware
        .route("/api/auth/me", web::get().to(get_current_user))
        .route("/api/auth/me", web::put().to(update_current_user))  // STUB

        // Things
        .route("/api/things", web::get().to(list_things))
        .route("/api/things", web::post().to(create_thing))
        .route("/api/things/query", web::get().to(query_things))  // STUB
        .route("/api/things/search", web::get().to(search_things))  // STUB
        .route("/api/things/upsert", web::put().to(upsert_thing))  // STUB
        .route("/api/things/bulk", web::post().to(bulk_create_things))  // STUB
        .route("/api/things/bulk", web::put().to(bulk_update_things))  // STUB
        .route("/api/things/bulk", web::delete().to(bulk_delete_things))  // STUB
        .route("/api/things/{id}", web::get().to(get_thing))
        .route("/api/things/{id}", web::put().to(update_thing))
        .route("/api/things/{id}", web::delete().to(delete_thing))
        .route("/api/things/{id}/backlinks", web::get().to(get_thing_backlinks))
        .route("/api/things/{id}/versions", web::get().to(list_thing_versions))  // STUB
        .route("/api/things/{id}/versions/{version}", web::get().to(get_thing_version))  // STUB
        .route("/api/things/{id}/versions/{version}/revert", web::post().to(revert_to_version))  // STUB
        .route("/api/things/{id}/restore", web::post().to(restore_thing))  // STUB

        // Photos
        .route("/api/upload", web::post().to(upload_photo))
        .route("/api/photos/{id}", web::get().to(get_photo))
        .route("/api/photos/{id}", web::put().to(update_photo))  // STUB
        .route("/api/photos/{id}", web::delete().to(delete_photo))  // STUB

        // API Keys
        .route("/api/keys", web::get().to(list_api_keys))
        .route("/api/keys", web::post().to(create_api_key))
        .route("/api/keys/{id}", web::get().to(get_api_key))  // STUB
        .route("/api/keys/{id}", web::put().to(update_api_key))  // STUB
        .route("/api/keys/{id}", web::delete().to(delete_api_key))

        // Kinds
        .route("/api/kinds", web::get().to(list_kinds))
        .route("/api/kinds", web::post().to(create_kind))
        .route("/api/kinds/{id}", web::get().to(get_kind))
        .route("/api/kinds/{id}", web::put().to(update_kind))
        .route("/api/kinds/{id}", web::delete().to(delete_kind))

        // Tags - STUBS
        .route("/api/tags", web::get().to(list_tags))
        .route("/api/tags", web::post().to(create_tag))

        // Views - STUBS
        .route("/api/views", web::get().to(list_views))
        .route("/api/views", web::post().to(create_view))
        .route("/api/views/{id}", web::get().to(get_view))
        .route("/api/views/{id}", web::put().to(update_view))
        .route("/api/views/{id}", web::delete().to(delete_view))

        // Export/Import - STUBS
        .route("/api/export", web::get().to(export_data))
        .route("/api/import", web::post().to(import_data))

        // Admin - STUBS
        .route("/api/admin/users", web::get().to(list_users))
        .route("/api/admin/users/{id}/lock", web::put().to(lock_user))
        .route("/api/admin/users/{id}/unlock", web::put().to(unlock_user))
        .route("/api/admin/users/{id}", web::delete().to(delete_user))

        // Follows
        .route("/api/friends", web::post().to(add_friend))          // NEW: Federated friend management
        .route("/api/follows/create-token", web::post().to(create_follow_token))  // NEW: Create verification token
        .route("/api/follows/{user_id}", web::delete().to(unfollow_user))
        .route("/api/follows/followers", web::get().to(get_followers))
        .route("/api/follows/following", web::get().to(get_following))
        .route("/api/follows/mutuals", web::get().to(get_mutuals))

        // Federation endpoints (no auth required - called by friend nodes)
        .route("/api/fed/notify-follow", web::post().to(notify_follow))  // NEW: Receive follow notification
        .route("/api/fed/verify-follow", web::post().to(verify_follow))  // NEW: Verify follow token
        .route("/api/fed/things/{user_id}", web::get().to(get_friend_visible_things))  // NEW: Fetch friend-visible content

        // Feed
        .route("/api/feed/friends", web::get().to(get_friend_feed))

        // Notifications
        .route("/api/notifications", web::get().to(list_notifications))
        .route("/api/notifications/unread-count", web::get().to(get_unread_count))
        .route("/api/notifications/read-all", web::put().to(mark_all_read))
        .route("/api/notifications/settings", web::get().to(get_notification_settings))
        .route("/api/notifications/settings", web::put().to(update_notification_settings))
        .route("/api/notifications/inbound", web::post().to(receive_inbound_notification))
        .route("/api/notifications/{id}/read", web::put().to(mark_notification_read))
        .route("/api/notifications/{id}", web::delete().to(delete_notification))

        // Reactions
        .route("/api/things/{id}/reactions", web::get().to(get_reactions))
        .route("/api/things/{id}/reactions", web::post().to(add_reaction))
        .route("/api/things/{thing_id}/reactions/{reaction_type}", web::delete().to(remove_reaction))

        // Frontend assets and SPA routing
        .route("/assets/{path:.*}", web::get().to(serve_assets))
        .route("/favicon.svg", web::get().to(serve_assets))
        .default_service(web::route().to(serve_frontend));
}
