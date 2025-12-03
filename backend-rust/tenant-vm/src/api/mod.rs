use actix_multipart::Multipart;
use actix_web::{cookie::{Cookie, SameSite, time::Duration}, web, HttpResponse, Responder};
use chrono::Utc;
use futures_util::StreamExt;
use serde::Deserialize;
use std::env;
use std::sync::Arc;

use crate::auth::{has_scope, AuthService, AuthUser};
use crate::models::*;
use crate::store::{Store, StoreError};

// Cookie settings - 6 months in seconds
const COOKIE_MAX_AGE_SECONDS: i64 = 6 * 30 * 24 * 60 * 60;

pub struct AppState {
    pub store: Arc<Store>,
    pub auth_service: Arc<AuthService>,
}

// ==================== Health Check ====================

pub async fn health() -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "ok",
        "timestamp": Utc::now().to_rfc3339()
    }))
}

// ==================== Auth Status ====================

pub async fn auth_status() -> impl Responder {
    // Check if running as sandbox user (username is "sandbox")
    let owner_username = env::var("OWNER_USERNAME").unwrap_or_default();
    let sandbox_mode = owner_username == "sandbox";

    // Server always has an owner (created at startup from env vars)
    // No registration - owner is pre-configured
    // In sandbox mode, auth is disabled so anyone can use it
    HttpResponse::Ok().json(serde_json::json!({
        "hasOwner": true,
        "registrationEnabled": false,
        "sandboxMode": sandbox_mode,
        "authDisabled": sandbox_mode
    }))
}

// ==================== Auth Endpoints ====================

pub async fn register(
    state: web::Data<AppState>,
    body: web::Json<RegisterRequest>,
) -> impl Responder {
    let password_hash = match state.auth_service.hash_password(&body.password) {
        Ok(hash) => hash,
        Err(_) => return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to hash password")),
    };

    let mut user = User {
        id: String::new(),
        username: body.username.clone(),
        email: body.email.clone(),
        password_hash,
        display_name: body.display_name.clone().unwrap_or_else(|| body.username.clone()),
        bio: String::new(),
        avatar_url: String::new(),
        is_admin: false,
        is_locked: false,
        recovery_hash: String::new(),
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };

    if let Err(e) = state.store.create_user(&mut user) {
        return HttpResponse::BadRequest().json(ApiResponse::<()>::error(format!("Failed to create user: {}", e)));
    }

    let token = match state.auth_service.generate_token(&user.id) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to generate token")),
    };

    // Set auth cookie for browser sessions
    let cookie = Cookie::build("tenant_auth", token.clone())
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(COOKIE_MAX_AGE_SECONDS))
        .finish();

    HttpResponse::Created()
        .cookie(cookie)
        .json(ApiResponse::success(LoginResponse { token, user }))
}

pub async fn login(
    state: web::Data<AppState>,
    body: web::Json<LoginRequest>,
) -> impl Responder {
    let user = match state.store.get_user_by_username(&body.username) {
        Ok(u) => u,
        Err(StoreError::NotFound(_)) => {
            return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Invalid credentials"));
        }
        Err(_) => {
            return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Database error"));
        }
    };

    if user.is_locked {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Account is locked"));
    }

    let valid = state.auth_service
        .verify_password(&body.password, &user.password_hash)
        .unwrap_or(false);

    if !valid {
        return HttpResponse::Unauthorized().json(ApiResponse::<()>::error("Invalid credentials"));
    }

    let token = match state.auth_service.generate_token(&user.id) {
        Ok(t) => t,
        Err(_) => return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to generate token")),
    };

    // Set auth cookie for browser sessions
    let cookie = Cookie::build("tenant_auth", token.clone())
        .path("/")
        .http_only(true)
        .same_site(SameSite::Lax)
        .max_age(Duration::seconds(COOKIE_MAX_AGE_SECONDS))
        .finish();

    HttpResponse::Ok()
        .cookie(cookie)
        .json(ApiResponse::success(LoginResponse { token, user }))
}

pub async fn get_current_user(
    state: web::Data<AppState>,
    auth_user: AuthUser,
) -> impl Responder {
    match state.store.get_user(&auth_user.user_id) {
        Ok(user) => HttpResponse::Ok().json(ApiResponse::success(user)),
        Err(_) => HttpResponse::NotFound().json(ApiResponse::<()>::error("User not found")),
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

    HttpResponse::Ok()
        .cookie(cookie)
        .json(ApiResponse::<()>::success(()))
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
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Missing scope: keys:manage"));
    }

    match state.store.list_api_keys(&auth_user.user_id) {
        Ok(keys) => HttpResponse::Ok().json(ApiResponse::success(keys)),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(format!("Failed to list API keys: {}", e))),
    }
}

pub async fn create_api_key(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    body: web::Json<CreateApiKeyRequest>,
) -> impl Responder {
    if !has_scope(&auth_user, "keys:manage") && auth_user.is_api_key {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Missing scope: keys:manage"));
    }

    // Validate scopes
    for scope in &body.scopes {
        if !API_KEY_SCOPES.contains(&scope.as_str()) {
            return HttpResponse::BadRequest().json(ApiResponse::<()>::error(format!("Invalid scope: {}", scope)));
        }
    }

    let raw_key = AuthService::generate_api_key();
    let key_hash = match state.auth_service.hash_password(&raw_key) {
        Ok(h) => h,
        Err(_) => return HttpResponse::InternalServerError().json(ApiResponse::<()>::error("Failed to hash key")),
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
            // Return the raw key only on creation
            HttpResponse::Created().json(serde_json::json!({
                "success": true,
                "data": {
                    "key": raw_key,
                    "id": api_key.id,
                    "name": api_key.name,
                    "scopes": api_key.scopes,
                    "key_prefix": api_key.key_prefix,
                    "created_at": api_key.created_at
                }
            }))
        }
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(format!("Failed to create API key: {}", e))),
    }
}

pub async fn delete_api_key(
    state: web::Data<AppState>,
    auth_user: AuthUser,
    path: web::Path<String>,
) -> impl Responder {
    if !has_scope(&auth_user, "keys:manage") && auth_user.is_api_key {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Missing scope: keys:manage"));
    }

    let id = path.into_inner();
    match state.store.delete_api_key(&id, &auth_user.user_id) {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(StoreError::NotFound(_)) => {
            HttpResponse::NotFound().json(ApiResponse::<()>::error("API key not found"))
        }
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(format!("Failed to delete API key: {}", e))),
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

// ==================== Route Configuration ====================

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg
        // Health check
        .route("/health", web::get().to(health))

        // Auth routes (no auth required)
        .route("/api/auth/status", web::get().to(auth_status))
        .route("/api/auth/register", web::post().to(register))
        .route("/api/auth/login", web::post().to(login))
        .route("/api/auth/logout", web::post().to(logout))

        // Protected routes - will need auth middleware
        .route("/api/auth/me", web::get().to(get_current_user))

        // Things
        .route("/api/things", web::get().to(list_things))
        .route("/api/things", web::post().to(create_thing))
        .route("/api/things/{id}", web::get().to(get_thing))
        .route("/api/things/{id}", web::put().to(update_thing))
        .route("/api/things/{id}", web::delete().to(delete_thing))
        .route("/api/things/{id}/backlinks", web::get().to(get_thing_backlinks))

        // Photos
        .route("/api/upload", web::post().to(upload_photo))
        .route("/api/photos/{id}", web::get().to(get_photo))

        // API Keys
        .route("/api/keys", web::get().to(list_api_keys))
        .route("/api/keys", web::post().to(create_api_key))
        .route("/api/keys/{id}", web::delete().to(delete_api_key))

        // Kinds
        .route("/api/kinds", web::get().to(list_kinds))
        .route("/api/kinds", web::post().to(create_kind))
        .route("/api/kinds/{id}", web::get().to(get_kind))
        .route("/api/kinds/{id}", web::put().to(update_kind))
        .route("/api/kinds/{id}", web::delete().to(delete_kind));
}
