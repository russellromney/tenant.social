use actix_web::{dev::{Service, ServiceRequest, ServiceResponse, Transform}, Error, HttpResponse};
use chrono::{DateTime, Utc, Timelike};
use futures_util::future::{ok, Ready};
use rusqlite::params;
use serde::Serialize;
use std::collections::HashMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::sync::mpsc::{channel, Sender};
use std::task::{Context, Poll};

enum MetricUpdate {
    Record { path: String, method: String, status_code: u16, timestamp: DateTime<Utc> },
    Shutdown,
}

#[derive(Clone)]
pub struct MetricsCollector {
    db_path: PathBuf,
    cache: Arc<Mutex<HashMap<String, u64>>>, // Overall counts for quick access
    start_time: DateTime<Utc>,
    tx: Sender<MetricUpdate>,
    session_api_calls: Arc<Mutex<u64>>, // Track API calls in current session
    cold_start: Arc<Mutex<ColdStartMetrics>>,
}

#[derive(Serialize)]
pub struct EndpointStats {
    pub path: String,
    pub total_count: u64,
    pub last_24h_count: u64,
}

#[derive(Serialize)]
pub struct MinuteMetric {
    pub timestamp: String,
    pub path: String,
    pub method: String,
    pub count: u64,
}

#[derive(Serialize)]
pub struct StatusCodeBreakdown {
    pub status_code: u16,
    pub count: u64,
    pub percentage: f64,
}

#[derive(Serialize)]
pub struct UptimeRecord {
    pub started_at: String,
    pub stopped_at: Option<String>,
    pub duration_secs: Option<i64>,
    pub api_call_count: Option<i64>,
    pub shutdown_reason: Option<String>,
}

#[derive(Serialize)]
pub struct MetricsResponse {
    pub endpoints: Vec<EndpointStats>,
    pub total_calls: u64,
    pub current_uptime_secs: i64,
    pub total_uptime_secs: i64,
    pub restart_count: u64,
    pub last_restart: Option<String>,
}

#[derive(Serialize, Clone)]
pub struct ColdStartMetrics {
    pub binary_start: DateTime<Utc>,
    pub metrics_init: DateTime<Utc>,
    pub server_listening: Option<DateTime<Utc>>,
    pub first_request: Option<DateTime<Utc>>,
    // Computed durations in milliseconds
    pub init_duration_ms: Option<i64>,
    pub time_to_first_request_ms: Option<i64>,
}

impl MetricsCollector {
    pub fn new(db_path: PathBuf) -> Self {
        let start_time = Utc::now();

        // Create channel for async writes
        let (tx, rx) = channel::<MetricUpdate>();

        let db_path_clone = db_path.clone();

        // Initialize database on main thread first
        if let Err(e) = Self::init_db(&db_path) {
            log::error!("Failed to initialize metrics database: {}", e);
        }

        // Record startup
        if let Err(e) = Self::record_startup(&db_path, start_time) {
            log::error!("Failed to record startup: {}", e);
        }

        let metrics_init = Utc::now();

        let collector = MetricsCollector {
            db_path,
            cache: Arc::new(Mutex::new(HashMap::new())),
            start_time,
            tx,
            session_api_calls: Arc::new(Mutex::new(0)),
            cold_start: Arc::new(Mutex::new(ColdStartMetrics {
                binary_start: start_time, // Will be updated from main.rs
                metrics_init,
                server_listening: None,
                first_request: None,
                init_duration_ms: None,
                time_to_first_request_ms: None,
            })),
        };

        // Load cached totals
        if let Err(e) = collector.load_cache() {
            log::error!("Failed to load metrics cache: {}", e);
        }

        // Start background writer thread
        std::thread::spawn(move || {
            loop {
                match rx.recv() {
                    Ok(MetricUpdate::Record { path, method, status_code, timestamp }) => {
                        if let Err(e) = Self::persist_metric(&db_path_clone, &path, &method, status_code, timestamp) {
                            log::error!("Failed to persist metric: {}", e);
                        }
                    }
                    Ok(MetricUpdate::Shutdown) | Err(_) => {
                        break;
                    }
                }
            }
        });

        collector
    }

    fn init_db(db_path: &PathBuf) -> Result<(), rusqlite::Error> {
        let conn = rusqlite::Connection::open(db_path)?;

        // Time-series metrics by minute
        conn.execute(
            "CREATE TABLE IF NOT EXISTS minute_metrics (
                timestamp TEXT NOT NULL,
                path TEXT NOT NULL,
                method TEXT NOT NULL,
                status_code INTEGER NOT NULL DEFAULT 200,
                count INTEGER NOT NULL DEFAULT 1,
                PRIMARY KEY (timestamp, path, method, status_code)
            )",
            [],
        )?;

        // Index for efficient queries
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_minute_metrics_timestamp
             ON minute_metrics(timestamp DESC)",
            [],
        )?;

        conn.execute(
            "CREATE TABLE IF NOT EXISTS uptime_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                stopped_at TEXT,
                duration_secs INTEGER,
                api_call_count INTEGER DEFAULT 0,
                shutdown_reason TEXT
            )",
            [],
        )?;

        // Migration: Add new columns if they don't exist
        // Check if api_call_count column exists
        let has_api_call_count: bool = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('uptime_records') WHERE name='api_call_count'",
            [],
            |row| {
                let count: i32 = row.get(0)?;
                Ok(count > 0)
            },
        ).unwrap_or(false);

        if !has_api_call_count {
            conn.execute("ALTER TABLE uptime_records ADD COLUMN api_call_count INTEGER DEFAULT 0", [])?;
            log::info!("Added api_call_count column to uptime_records");
        }

        // Check if shutdown_reason column exists
        let has_shutdown_reason: bool = conn.query_row(
            "SELECT COUNT(*) FROM pragma_table_info('uptime_records') WHERE name='shutdown_reason'",
            [],
            |row| {
                let count: i32 = row.get(0)?;
                Ok(count > 0)
            },
        ).unwrap_or(false);

        if !has_shutdown_reason {
            conn.execute("ALTER TABLE uptime_records ADD COLUMN shutdown_reason TEXT", [])?;
            log::info!("Added shutdown_reason column to uptime_records");
        }

        Ok(())
    }

    fn record_startup(db_path: &PathBuf, start_time: DateTime<Utc>) -> Result<(), rusqlite::Error> {
        let conn = rusqlite::Connection::open(db_path)?;
        conn.execute(
            "INSERT INTO uptime_records (started_at) VALUES (?1)",
            params![start_time.to_rfc3339()],
        )?;
        Ok(())
    }

    fn minute_key(timestamp: DateTime<Utc>) -> String {
        // Truncate to minute precision
        timestamp
            .with_second(0)
            .unwrap()
            .with_nanosecond(0)
            .unwrap()
            .to_rfc3339()
    }

    fn persist_metric(db_path: &PathBuf, path: &str, method: &str, status_code: u16, timestamp: DateTime<Utc>) -> Result<(), rusqlite::Error> {
        let conn = rusqlite::Connection::open(db_path)?;
        let minute = Self::minute_key(timestamp);

        // Increment count for this minute/path/method/status_code combination
        conn.execute(
            "INSERT INTO minute_metrics (timestamp, path, method, status_code, count) VALUES (?1, ?2, ?3, ?4, 1)
             ON CONFLICT(timestamp, path, method, status_code) DO UPDATE SET count = count + 1",
            params![minute, path, method, status_code],
        )?;

        Ok(())
    }

    fn load_cache(&self) -> Result<(), rusqlite::Error> {
        let conn = rusqlite::Connection::open(&self.db_path)?;

        // Load total counts per path
        let mut stmt = conn.prepare(
            "SELECT path, SUM(count) as total FROM minute_metrics GROUP BY path"
        )?;

        let rows = stmt.query_map([], |row| {
            let path: String = row.get(0)?;
            let total: u64 = row.get(1)?;
            Ok((path, total))
        })?;

        let mut cache = self.cache.lock().unwrap();
        for row in rows {
            if let Ok((path, total)) = row {
                cache.insert(path, total);
            }
        }

        Ok(())
    }

    pub fn record(&self, path: &str, method: &str, status_code: u16) {
        let timestamp = Utc::now();

        // Update in-memory cache
        {
            let mut cache = self.cache.lock().unwrap();
            *cache.entry(path.to_string()).or_insert(0) += 1;
        }

        // Increment session API call counter
        {
            let mut session_calls = self.session_api_calls.lock().unwrap();
            *session_calls += 1;
        }

        // Track first request for cold start metrics
        {
            let mut cold_start = self.cold_start.lock().unwrap();
            if cold_start.first_request.is_none() {
                cold_start.first_request = Some(timestamp);
                // Calculate time to first request
                cold_start.time_to_first_request_ms = Some(
                    (timestamp - cold_start.binary_start).num_milliseconds()
                );
            }
        }

        // Send to background thread for persistence (non-blocking)
        let _ = self.tx.send(MetricUpdate::Record {
            path: path.to_string(),
            method: method.to_string(),
            status_code,
            timestamp,
        });
    }

    pub fn set_binary_start(&self, start_time: DateTime<Utc>) {
        let mut cold_start = self.cold_start.lock().unwrap();
        cold_start.binary_start = start_time;
    }

    pub fn mark_server_listening(&self) {
        let timestamp = Utc::now();
        let mut cold_start = self.cold_start.lock().unwrap();
        cold_start.server_listening = Some(timestamp);
        // Calculate init duration
        cold_start.init_duration_ms = Some(
            (timestamp - cold_start.binary_start).num_milliseconds()
        );
    }

    pub fn get_cold_start_metrics(&self) -> ColdStartMetrics {
        self.cold_start.lock().unwrap().clone()
    }

    pub fn get_metrics(&self) -> MetricsResponse {
        let conn = rusqlite::Connection::open(&self.db_path).ok();

        let endpoints = if let Some(conn) = &conn {
            self.get_endpoint_stats(&conn).unwrap_or_default()
        } else {
            Vec::new()
        };

        let cache = self.cache.lock().unwrap();
        let total_calls = cache.values().sum::<u64>();
        let current_uptime_secs = (Utc::now() - self.start_time).num_seconds();

        let (total_uptime_secs, restart_count, last_restart) = if let Some(conn) = &conn {
            self.get_uptime_stats(&conn, current_uptime_secs)
                .unwrap_or((current_uptime_secs, 1, Some(self.start_time.to_rfc3339())))
        } else {
            (current_uptime_secs, 1, Some(self.start_time.to_rfc3339()))
        };

        MetricsResponse {
            endpoints,
            total_calls,
            current_uptime_secs,
            total_uptime_secs,
            restart_count,
            last_restart,
        }
    }

    fn get_endpoint_stats(&self, conn: &rusqlite::Connection) -> Result<Vec<EndpointStats>, rusqlite::Error> {
        let now = Utc::now();
        let day_ago = (now - chrono::Duration::hours(24)).to_rfc3339();

        // Get total and last 24h counts
        let mut stmt = conn.prepare(
            "SELECT
                path,
                SUM(count) as total_count,
                SUM(CASE WHEN timestamp >= ?1 THEN count ELSE 0 END) as last_24h_count
             FROM minute_metrics
             GROUP BY path
             ORDER BY total_count DESC"
        )?;

        let rows = stmt.query_map(params![day_ago], |row| {
            Ok(EndpointStats {
                path: row.get(0)?,
                total_count: row.get(1)?,
                last_24h_count: row.get(2)?,
            })
        })?;

        let mut stats = Vec::new();
        for row in rows {
            if let Ok(stat) = row {
                stats.push(stat);
            }
        }

        Ok(stats)
    }

    fn get_uptime_stats(&self, conn: &rusqlite::Connection, current_uptime: i64) -> Result<(i64, u64, Option<String>), rusqlite::Error> {
        // Get total uptime from completed sessions
        let mut stmt = conn.prepare("SELECT SUM(duration_secs) FROM uptime_records WHERE duration_secs IS NOT NULL")?;
        let total_previous: i64 = stmt.query_row([], |row| row.get(0)).unwrap_or(0);

        // Add current session
        let total_uptime = total_previous + current_uptime;

        // Get restart count
        let mut stmt = conn.prepare("SELECT COUNT(*) FROM uptime_records")?;
        let restart_count: u64 = stmt.query_row([], |row| row.get(0))?;

        // Get last restart time
        let mut stmt = conn.prepare("SELECT started_at FROM uptime_records ORDER BY id DESC LIMIT 1")?;
        let last_restart: Option<String> = stmt.query_row([], |row| row.get(0)).ok();

        Ok((total_uptime, restart_count, last_restart))
    }

    pub fn get_time_series(&self, hours: i64) -> Result<Vec<MinuteMetric>, rusqlite::Error> {
        let conn = rusqlite::Connection::open(&self.db_path)?;
        let since = (Utc::now() - chrono::Duration::hours(hours)).to_rfc3339();

        let mut stmt = conn.prepare(
            "SELECT timestamp, path, method, count
             FROM minute_metrics
             WHERE timestamp >= ?1
             ORDER BY timestamp DESC
             LIMIT 1000"
        )?;

        let rows = stmt.query_map(params![since], |row| {
            Ok(MinuteMetric {
                timestamp: row.get(0)?,
                path: row.get(1)?,
                method: row.get(2)?,
                count: row.get(3)?,
            })
        })?;

        let mut metrics = Vec::new();
        for row in rows {
            if let Ok(metric) = row {
                metrics.push(metric);
            }
        }

        Ok(metrics)
    }

    pub fn get_uptime_history(&self) -> Result<Vec<UptimeRecord>, rusqlite::Error> {
        let conn = rusqlite::Connection::open(&self.db_path)?;
        let mut stmt = conn.prepare(
            "SELECT started_at, stopped_at, duration_secs, api_call_count, shutdown_reason FROM uptime_records ORDER BY id DESC LIMIT 100"
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(UptimeRecord {
                started_at: row.get(0)?,
                stopped_at: row.get(1)?,
                duration_secs: row.get(2)?,
                api_call_count: row.get(3)?,
                shutdown_reason: row.get(4)?,
            })
        })?;

        let mut records = Vec::new();
        for row in rows {
            if let Ok(record) = row {
                records.push(record);
            }
        }

        Ok(records)
    }

    pub fn record_shutdown(&self, reason: &str) -> Result<(), rusqlite::Error> {
        let conn = rusqlite::Connection::open(&self.db_path)?;
        let now = Utc::now();
        let duration = (now - self.start_time).num_seconds();
        let api_calls = *self.session_api_calls.lock().unwrap();

        conn.execute(
            "UPDATE uptime_records SET stopped_at = ?1, duration_secs = ?2, api_call_count = ?3, shutdown_reason = ?4 WHERE stopped_at IS NULL",
            params![now.to_rfc3339(), duration, api_calls as i64, reason],
        )?;

        // Send shutdown signal to writer thread
        let _ = self.tx.send(MetricUpdate::Shutdown);

        Ok(())
    }

    pub fn reset(&self) -> Result<(), rusqlite::Error> {
        let conn = rusqlite::Connection::open(&self.db_path)?;
        conn.execute("DELETE FROM minute_metrics", [])?;

        let mut cache = self.cache.lock().unwrap();
        cache.clear();

        Ok(())
    }

    pub fn cleanup_old_metrics(&self, days: i64) -> Result<usize, rusqlite::Error> {
        let conn = rusqlite::Connection::open(&self.db_path)?;
        let cutoff = (Utc::now() - chrono::Duration::days(days)).to_rfc3339();

        let deleted = conn.execute(
            "DELETE FROM minute_metrics WHERE timestamp < ?1",
            params![cutoff],
        )?;

        Ok(deleted)
    }

    pub fn get_status_code_breakdown(&self, hours: i64) -> Result<Vec<StatusCodeBreakdown>, rusqlite::Error> {
        let conn = rusqlite::Connection::open(&self.db_path)?;
        let since = (Utc::now() - chrono::Duration::hours(hours)).to_rfc3339();

        // Get total count first
        let mut stmt = conn.prepare(
            "SELECT SUM(count) FROM minute_metrics WHERE timestamp >= ?1"
        )?;
        let total: i64 = stmt.query_row(params![since], |row| row.get(0)).unwrap_or(0);

        if total == 0 {
            return Ok(Vec::new());
        }

        // Get breakdown by status code
        let mut stmt = conn.prepare(
            "SELECT status_code, SUM(count) as count
             FROM minute_metrics
             WHERE timestamp >= ?1
             GROUP BY status_code
             ORDER BY status_code"
        )?;

        let rows = stmt.query_map(params![since], |row| {
            let status_code: u16 = row.get(0)?;
            let count: u64 = row.get(1)?;
            let percentage = (count as f64 / total as f64) * 100.0;

            Ok(StatusCodeBreakdown {
                status_code,
                count,
                percentage,
            })
        })?;

        let mut breakdown = Vec::new();
        for row in rows {
            if let Ok(item) = row {
                breakdown.push(item);
            }
        }

        Ok(breakdown)
    }
}

// Implement Drop to record shutdown time
impl Drop for MetricsCollector {
    fn drop(&mut self) {
        // Normal shutdown - could be graceful termination or process exit
        let _ = self.record_shutdown("normal");
    }
}

// Middleware implementation
impl<S, B> Transform<S, ServiceRequest> for MetricsCollector
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = MetricsMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(MetricsMiddleware {
            service,
            metrics: self.clone(),
        })
    }
}

pub struct MetricsMiddleware<S> {
    service: S,
    metrics: MetricsCollector,
}

impl<S, B> Service<ServiceRequest> for MetricsMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error>,
    S::Future: 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(cx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let path = req.path().to_string();
        let method = req.method().to_string();
        let should_track = path.starts_with("/api/") || path == "/health";
        let metrics = self.metrics.clone();

        let fut = self.service.call(req);

        Box::pin(async move {
            let res = fut.await?;

            // Record metrics after response, capturing status code
            if should_track {
                let status_code = res.status().as_u16();
                metrics.record(&path, &method, status_code);
            }

            Ok(res)
        })
    }
}

// API endpoint handlers
pub async fn get_metrics_handler(
    metrics: actix_web::web::Data<MetricsCollector>,
) -> HttpResponse {
    let metrics_data = metrics.get_metrics();
    HttpResponse::Ok().json(metrics_data)
}

pub async fn get_time_series_handler(
    metrics: actix_web::web::Data<MetricsCollector>,
    query: actix_web::web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let hours: i64 = query.get("hours")
        .and_then(|h| h.parse().ok())
        .unwrap_or(24);

    match metrics.get_time_series(hours) {
        Ok(series) => HttpResponse::Ok().json(series),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to fetch time series: {}", e)
        }))
    }
}

pub async fn get_uptime_history_handler(
    metrics: actix_web::web::Data<MetricsCollector>,
) -> HttpResponse {
    match metrics.get_uptime_history() {
        Ok(history) => HttpResponse::Ok().json(history),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to fetch uptime history: {}", e)
        }))
    }
}

pub async fn reset_metrics_handler(
    metrics: actix_web::web::Data<MetricsCollector>,
) -> HttpResponse {
    match metrics.reset() {
        Ok(_) => HttpResponse::Ok().json(serde_json::json!({
            "message": "Metrics reset successfully"
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to reset metrics: {}", e)
        }))
    }
}

pub async fn cleanup_old_metrics_handler(
    metrics: actix_web::web::Data<MetricsCollector>,
    query: actix_web::web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let days: i64 = query.get("days")
        .and_then(|d| d.parse().ok())
        .unwrap_or(30);

    match metrics.cleanup_old_metrics(days) {
        Ok(deleted) => HttpResponse::Ok().json(serde_json::json!({
            "message": format!("Deleted {} old metric records", deleted),
            "deleted_count": deleted
        })),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to cleanup metrics: {}", e)
        }))
    }
}

pub async fn get_status_breakdown_handler(
    metrics: actix_web::web::Data<MetricsCollector>,
    query: actix_web::web::Query<HashMap<String, String>>,
) -> HttpResponse {
    let hours: i64 = query.get("hours")
        .and_then(|h| h.parse().ok())
        .unwrap_or(24);

    match metrics.get_status_code_breakdown(hours) {
        Ok(breakdown) => HttpResponse::Ok().json(breakdown),
        Err(e) => HttpResponse::InternalServerError().json(serde_json::json!({
            "error": format!("Failed to fetch status breakdown: {}", e)
        }))
    }
}

pub async fn get_cold_start_handler(
    metrics: actix_web::web::Data<MetricsCollector>,
) -> HttpResponse {
    let cold_start = metrics.get_cold_start_metrics();
    HttpResponse::Ok().json(cold_start)
}
