mod api;
mod auth;
mod models;
mod store;

use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpServer};
use chrono::Utc;
use std::env;
use std::sync::Arc;

use api::AppState;
use auth::AuthService;
use models::{Attribute, Kind, User};
use store::Store;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Initialize logger
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    // Load environment variables
    dotenvy::dotenv().ok();

    // Get configuration from environment
    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "8069".to_string())
        .parse()
        .expect("PORT must be a number");

    let db_path = env::var("DATABASE_PATH").unwrap_or_else(|_| "tenant.db".to_string());

    let jwt_secret = env::var("JWT_SECRET").unwrap_or_else(|_| {
        log::warn!("JWT_SECRET not set, using default (not secure for production!)");
        "default_jwt_secret_change_me".to_string()
    });

    // Initialize store
    let store = Arc::new(
        Store::new(&db_path).expect("Failed to initialize database"),
    );

    // Initialize auth service
    let auth_service = Arc::new(AuthService::new(jwt_secret, store.clone()));

    // Auto-create owner user from environment variables if no users exist
    let owner_username = env::var("OWNER_USERNAME").ok();
    let owner_password = env::var("OWNER_PASSWORD").ok();

    if let (Some(username), Some(password)) = (owner_username, owner_password) {
        let user_count = store.count_users().expect("Failed to count users");
        if user_count == 0 {
            log::info!("Creating owner user from environment: {}", username);
            let password_hash = auth_service
                .hash_password(&password)
                .expect("Failed to hash password");

            let mut owner_user = User {
                id: String::new(),
                username: username.clone(),
                email: format!("{}@tenant.social", username),
                password_hash,
                display_name: username,
                bio: String::new(),
                avatar_url: String::new(),
                is_admin: true,
                is_locked: false,
                recovery_hash: String::new(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            };

            store
                .create_user(&mut owner_user)
                .expect("Failed to create owner user");
            log::info!("Owner user created successfully");

            // Create default Kinds for the owner
            create_default_kinds(&store, &owner_user.id);
        }
    }

    // Also check if owner exists but has no kinds (upgrade scenario)
    if let Ok(user) = store.get_user_by_username(
        &env::var("OWNER_USERNAME").unwrap_or_default(),
    ) {
        let kind_count = store.count_kinds(&user.id).unwrap_or(0);
        if kind_count == 0 {
            log::info!("Creating default Kinds for existing owner user");
            create_default_kinds(&store, &user.id);
        }
    }

    log::info!("Starting tenant-vm server on port {}", port);
    log::info!("Database: {}", db_path);

    // Start HTTP server
    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .app_data(web::Data::new(AppState {
                store: store.clone(),
                auth_service: auth_service.clone(),
            }))
            .configure(api::configure_routes)
    })
    .bind(("0.0.0.0", port))?
    .workers(1) // Single worker for minimal memory
    .run()
    .await
}

/// Create default Kinds for a user
/// Matches the frontend defaults: note, link, task, gallery
fn create_default_kinds(store: &Arc<Store>, user_id: &str) {
    let default_kinds = vec![
        Kind {
            id: String::new(),
            user_id: user_id.to_string(),
            name: "note".to_string(),
            icon: "pencil".to_string(),
            template: "default".to_string(),
            attributes: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        Kind {
            id: String::new(),
            user_id: user_id.to_string(),
            name: "link".to_string(),
            icon: "link".to_string(),
            template: "link".to_string(),
            attributes: vec![Attribute {
                name: "url".to_string(),
                attr_type: "url".to_string(),
                required: true,
                options: String::new(),
            }],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        Kind {
            id: String::new(),
            user_id: user_id.to_string(),
            name: "task".to_string(),
            icon: "check".to_string(),
            template: "checklist".to_string(),
            attributes: vec![Attribute {
                name: "done".to_string(),
                attr_type: "checkbox".to_string(),
                required: false,
                options: String::new(),
            }],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        Kind {
            id: String::new(),
            user_id: user_id.to_string(),
            name: "gallery".to_string(),
            icon: "image".to_string(),
            template: "photo".to_string(),
            attributes: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
    ];

    for mut kind in default_kinds {
        if let Err(e) = store.create_kind(&mut kind) {
            log::error!("Failed to create default kind '{}': {}", kind.name, e);
        } else {
            log::info!("Created default kind: {}", kind.name);
        }
    }
}
