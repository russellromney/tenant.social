use actix_web::{web, HttpResponse, Responder};
use chrono::Utc;
use serde::Deserialize;
use std::env;
use std::sync::Arc;

use crate::auth::{has_scope, AuthService, AuthUser};
use crate::models::*;
use crate::store::{Store, StoreError};

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
    // Check if running in sandbox mode (for public tenant.social demo)
    let sandbox_mode = env::var("SANDBOX_MODE")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(false);

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

    HttpResponse::Created().json(ApiResponse::success(LoginResponse { token, user }))
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

    HttpResponse::Ok().json(ApiResponse::success(LoginResponse { token, user }))
}

pub async fn get_current_user(
    state: web::Data<AppState>,
    auth_user: web::ReqData<AuthUser>,
) -> impl Responder {
    match state.store.get_user(&auth_user.user_id) {
        Ok(user) => HttpResponse::Ok().json(ApiResponse::success(user)),
        Err(_) => HttpResponse::NotFound().json(ApiResponse::<()>::error("User not found")),
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
    auth_user: web::ReqData<AuthUser>,
    query: web::Query<ListThingsQuery>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:read") {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Missing scope: things:read"));
    }

    let limit = query.limit.unwrap_or(50).min(100);
    let offset = query.offset.unwrap_or(0);

    match state.store.list_things(&auth_user.user_id, query.thing_type.as_deref(), limit, offset) {
        Ok(things) => HttpResponse::Ok().json(ApiResponse::success(things)),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(format!("Failed to list things: {}", e))),
    }
}

pub async fn get_thing(
    state: web::Data<AppState>,
    auth_user: web::ReqData<AuthUser>,
    path: web::Path<String>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:read") {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Missing scope: things:read"));
    }

    let id = path.into_inner();
    match state.store.get_thing(&id) {
        Ok(thing) => {
            // Check ownership
            if thing.user_id != auth_user.user_id {
                return HttpResponse::NotFound().json(ApiResponse::<()>::error("Thing not found"));
            }
            HttpResponse::Ok().json(ApiResponse::success(thing))
        }
        Err(StoreError::NotFound(_)) => {
            HttpResponse::NotFound().json(ApiResponse::<()>::error("Thing not found"))
        }
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(format!("Failed to get thing: {}", e))),
    }
}

pub async fn create_thing(
    state: web::Data<AppState>,
    auth_user: web::ReqData<AuthUser>,
    body: web::Json<CreateThingRequest>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Missing scope: things:write"));
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
        Ok(_) => HttpResponse::Created().json(ApiResponse::success(thing)),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(format!("Failed to create thing: {}", e))),
    }
}

pub async fn update_thing(
    state: web::Data<AppState>,
    auth_user: web::ReqData<AuthUser>,
    path: web::Path<String>,
    body: web::Json<UpdateThingRequest>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:write") {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Missing scope: things:write"));
    }

    let id = path.into_inner();
    let mut thing = match state.store.get_thing(&id) {
        Ok(t) => t,
        Err(StoreError::NotFound(_)) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error("Thing not found"));
        }
        Err(e) => return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(format!("Failed to get thing: {}", e))),
    };

    // Check ownership
    if thing.user_id != auth_user.user_id {
        return HttpResponse::NotFound().json(ApiResponse::<()>::error("Thing not found"));
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
        Ok(_) => HttpResponse::Ok().json(ApiResponse::success(thing)),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(format!("Failed to update thing: {}", e))),
    }
}

pub async fn delete_thing(
    state: web::Data<AppState>,
    auth_user: web::ReqData<AuthUser>,
    path: web::Path<String>,
) -> impl Responder {
    if !has_scope(&auth_user, "things:delete") {
        return HttpResponse::Forbidden().json(ApiResponse::<()>::error("Missing scope: things:delete"));
    }

    let id = path.into_inner();

    // Verify ownership first
    match state.store.get_thing(&id) {
        Ok(thing) => {
            if thing.user_id != auth_user.user_id {
                return HttpResponse::NotFound().json(ApiResponse::<()>::error("Thing not found"));
            }
        }
        Err(StoreError::NotFound(_)) => {
            return HttpResponse::NotFound().json(ApiResponse::<()>::error("Thing not found"));
        }
        Err(e) => return HttpResponse::InternalServerError().json(ApiResponse::<()>::error(format!("Failed to get thing: {}", e))),
    }

    match state.store.delete_thing(&id) {
        Ok(_) => HttpResponse::NoContent().finish(),
        Err(e) => HttpResponse::InternalServerError().json(ApiResponse::<()>::error(format!("Failed to delete thing: {}", e))),
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

// ==================== API Keys Endpoints ====================

#[derive(Deserialize)]
pub struct CreateApiKeyRequest {
    name: String,
    scopes: Vec<String>,
}

pub async fn list_api_keys(
    state: web::Data<AppState>,
    auth_user: web::ReqData<AuthUser>,
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
    auth_user: web::ReqData<AuthUser>,
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
    auth_user: web::ReqData<AuthUser>,
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

// ==================== Route Configuration ====================

pub fn configure_routes(cfg: &mut web::ServiceConfig) {
    cfg
        // Health check
        .route("/health", web::get().to(health))

        // Auth routes (no auth required)
        .route("/api/auth/status", web::get().to(auth_status))
        .route("/api/auth/register", web::post().to(register))
        .route("/api/auth/login", web::post().to(login))

        // Protected routes - will need auth middleware
        .route("/api/auth/me", web::get().to(get_current_user))

        // Things
        .route("/api/things", web::get().to(list_things))
        .route("/api/things", web::post().to(create_thing))
        .route("/api/things/{id}", web::get().to(get_thing))
        .route("/api/things/{id}", web::put().to(update_thing))
        .route("/api/things/{id}", web::delete().to(delete_thing))

        // Photos
        .route("/api/photos/{id}", web::get().to(get_photo))

        // API Keys
        .route("/api/keys", web::get().to(list_api_keys))
        .route("/api/keys", web::post().to(create_api_key))
        .route("/api/keys/{id}", web::delete().to(delete_api_key));
}
