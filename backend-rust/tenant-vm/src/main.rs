mod api;
mod auth;
mod events;
mod models;
mod store;
mod metrics;

use actix_cors::Cors;
use actix_web::{middleware, web, App, HttpServer};
use chrono::Utc;
use std::env;
use std::path::PathBuf;
use std::sync::Arc;
#[cfg(unix)]
use std::os::unix::net::UnixListener as StdUnixListener;

use api::AppState;
use auth::AuthService;
use events::EventProcessor;
use models::{Attribute, Kind, User};
use store::Store;
use metrics::MetricsCollector;

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Capture binary start time FIRST (for cold start metrics)
    let binary_start = Utc::now();

    // Also capture startup time for hypervisor callback
    let startup_begin = std::time::Instant::now();

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

    // Initialize event processor for the notification/event system
    let event_processor = Arc::new(EventProcessor::new(store.clone()));

    // Initialize metrics collector with separate database
    let metrics_db = env::var("DATABASE_PATH")
        .unwrap_or_else(|_| "tenant.db".to_string())
        .replace(".db", "-metrics.db");
    let metrics_collector = MetricsCollector::new(PathBuf::from(metrics_db));

    // Update cold start metrics with actual binary start time
    metrics_collector.set_binary_start(binary_start);

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

    log::info!("Database: {}", db_path);

    // Check if we should use Unix socket
    let socket_path = env::var("SOCKET_PATH").ok();

    // Get user ID for reporting startup metrics
    let user_id = env::var("USER_ID").ok();

    // Mark server as listening (for cold start metrics)
    metrics_collector.mark_server_listening();

    // Create the server
    let server = HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header()
            .max_age(3600);

        App::new()
            .wrap(middleware::Logger::default())
            .wrap(cors)
            .wrap(metrics_collector.clone()) // Add metrics middleware
            // Register Store and AuthService individually for auth extractor
            .app_data(web::Data::new(store.clone()))
            .app_data(web::Data::new(auth_service.clone()))
            .app_data(web::Data::new(metrics_collector.clone()))
            // Also keep AppState for handlers that need both
            .app_data(web::Data::new(AppState {
                store: store.clone(),
                auth_service: auth_service.clone(),
                event_processor: event_processor.clone(),
            }))
            // Increase payload size limit for photo uploads (50MB)
            .app_data(web::PayloadConfig::new(50 * 1024 * 1024))
            .configure(api::configure_routes)
    })
    .workers(1); // Single worker for minimal memory

    // Bind to Unix socket or TCP port
    #[cfg(unix)]
    if let Some(ref socket) = socket_path {
        // Remove existing socket file if it exists
        if std::path::Path::new(socket).exists() {
            std::fs::remove_file(socket)?;
        }

        log::info!("Starting tenant-vm server on Unix socket: {}", socket);

        // Create a standard Unix listener and convert it
        let listener = StdUnixListener::bind(socket)?;

        // Report startup time to hypervisor now that we're ready to accept requests
        let startup_ms = startup_begin.elapsed().as_millis() as u64;
        log::info!("Tenant VM ready in {}ms", startup_ms);

        // Report to hypervisor if we have the necessary info
        if let Some(uid) = user_id {
            report_ready_to_hypervisor(&uid, startup_ms).await;
        }

        return server.listen_uds(listener)?.run().await;
    }

    log::info!("Starting tenant-vm server on port {}", port);

    // Report startup time
    let startup_ms = startup_begin.elapsed().as_millis() as u64;
    log::info!("Tenant VM ready in {}ms", startup_ms);

    // Report to hypervisor if we have the necessary info
    if let Some(uid) = user_id {
        report_ready_to_hypervisor(&uid, startup_ms).await;
    }

    server.bind(("0.0.0.0", port))?.run().await
}

/// Report to the hypervisor that we're ready to accept requests
async fn report_ready_to_hypervisor(user_id: &str, startup_ms: u64) {
    // Get hypervisor callback URL from environment
    let callback_url = match env::var("HYPERVISOR_CALLBACK_URL") {
        Ok(url) => url,
        Err(_) => return, // No callback configured, skip
    };

    let url = format!("{}/internal/tenant-ready/{}", callback_url, user_id);

    // Make async HTTP request to report readiness
    let client = reqwest::Client::new();
    match client.post(&url)
        .json(&serde_json::json!({ "startup_ms": startup_ms }))
        .timeout(std::time::Duration::from_millis(100))
        .send()
        .await
    {
        Ok(_) => log::debug!("Reported readiness to hypervisor"),
        Err(e) => log::warn!("Failed to report readiness to hypervisor: {}", e),
    }
}

/// Create default Kinds for a user
/// Matches the frontend defaults: note, link, task, gallery
fn create_default_kinds(store: &Arc<Store>, user_id: &str) {
    let default_kinds = vec![
        Kind {
            id: String::new(),
            user_id: user_id.to_string(),
            name: "note".to_string(),
            icon: "📝".to_string(),
            template: "default".to_string(),
            attributes: vec![],
            created_at: Utc::now(),
            updated_at: Utc::now(),
        },
        Kind {
            id: String::new(),
            user_id: user_id.to_string(),
            name: "link".to_string(),
            icon: "🔗".to_string(),
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
            icon: "✅".to_string(),
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
            icon: "🖼️".to_string(),
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
