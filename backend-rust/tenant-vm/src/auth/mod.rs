use actix_web::{dev::ServiceRequest, web, Error, FromRequest, HttpRequest};
use actix_web::dev::Payload;
use actix_web::error::ErrorUnauthorized;
use chrono::{Duration, Utc};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use std::env;
use std::pin::Pin;
use std::sync::Arc;
use std::future::Future;

use crate::store::Store;

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,      // user_id
    pub exp: i64,         // expiration timestamp
    pub iat: i64,         // issued at
}

pub struct AuthService {
    jwt_secret: String,
    store: Arc<Store>,
}

impl AuthService {
    pub fn new(jwt_secret: String, store: Arc<Store>) -> Self {
        Self { jwt_secret, store }
    }

    /// Hash a password using bcrypt
    pub fn hash_password(&self, password: &str) -> Result<String, bcrypt::BcryptError> {
        bcrypt::hash(password, 10)
    }

    /// Verify a password against a bcrypt hash
    pub fn verify_password(&self, password: &str, hash: &str) -> Result<bool, bcrypt::BcryptError> {
        bcrypt::verify(password, hash)
    }

    /// Generate a JWT token for a user (6 month expiration)
    pub fn generate_token(&self, user_id: &str) -> Result<String, jsonwebtoken::errors::Error> {
        let now = Utc::now();
        let exp = now + Duration::days(180); // 6 months

        let claims = Claims {
            sub: user_id.to_string(),
            exp: exp.timestamp(),
            iat: now.timestamp(),
        };

        encode(
            &Header::default(),
            &claims,
            &EncodingKey::from_secret(self.jwt_secret.as_bytes()),
        )
    }

    /// Validate a JWT token and return the claims
    pub fn validate_token(&self, token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
        let token_data = decode::<Claims>(
            token,
            &DecodingKey::from_secret(self.jwt_secret.as_bytes()),
            &Validation::default(),
        )?;
        Ok(token_data.claims)
    }

    /// Generate a random session token
    pub fn generate_session_token() -> String {
        use uuid::Uuid;
        format!("{}{}", Uuid::new_v4(), Uuid::new_v4())
            .replace("-", "")
    }

    /// Generate an API key (shown once to user)
    pub fn generate_api_key() -> String {
        use uuid::Uuid;
        format!("ts_{}", Uuid::new_v4().to_string().replace("-", ""))
    }

    /// Get the prefix of an API key for identification
    pub fn get_api_key_prefix(key: &str) -> String {
        key.chars().take(11).collect()
    }
}

/// Authenticated user info extracted from request
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
    pub is_api_key: bool,
    pub scopes: Vec<String>,
}

/// Implement FromRequest for AuthUser so it can be extracted directly in handlers
impl FromRequest for AuthUser {
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self, Self::Error>>>>;

    fn from_request(req: &HttpRequest, _payload: &mut Payload) -> Self::Future {
        let req = req.clone();

        Box::pin(async move {
            // Get the Store and AuthService from request app_data
            let store = req.app_data::<web::Data<Arc<Store>>>()
                .ok_or_else(|| ErrorUnauthorized("Server configuration error"))?;
            let auth_service = req.app_data::<web::Data<Arc<AuthService>>>()
                .ok_or_else(|| ErrorUnauthorized("Server configuration error"))?;

            // Check if running as sandbox user (username is "sandbox")
            let owner_username = env::var("OWNER_USERNAME").unwrap_or_default();
            if owner_username == "sandbox" {
                // In sandbox mode, look up the actual sandbox user from database
                let sandbox_user = store.get_user_by_username("sandbox")
                    .map_err(|_| ErrorUnauthorized("Sandbox user not found"))?;

                return Ok(AuthUser {
                    user_id: sandbox_user.id,
                    is_api_key: false,
                    scopes: vec!["*".to_string()],
                });
            }

            // Extract token from Authorization header or cookie
            let auth_header = req
                .headers()
                .get("Authorization")
                .and_then(|h| h.to_str().ok());

            // Try Authorization header first, then cookie
            let token = if let Some(header) = auth_header {
                header.strip_prefix("Bearer ").map(|t| t.to_string())
            } else {
                // Check for tenant_auth cookie
                req.cookie("tenant_auth").map(|c| c.value().to_string())
            };

            let token = token.ok_or_else(|| ErrorUnauthorized("Missing Authorization header or cookie"))?;

            // Check if it's an API key (starts with ts_)
            if token.starts_with("ts_") {
                let prefix = AuthService::get_api_key_prefix(&token);
                let api_key = store
                    .get_api_key_by_prefix(&prefix)
                    .map_err(|_| ErrorUnauthorized("Invalid API key"))?;

                // Verify the full key
                if !auth_service
                    .verify_password(&token, &api_key.key_hash)
                    .unwrap_or(false)
                {
                    return Err(ErrorUnauthorized("Invalid API key").into());
                }

                // Check expiration
                if let Some(expires_at) = api_key.expires_at {
                    if expires_at < Utc::now() {
                        return Err(ErrorUnauthorized("API key expired").into());
                    }
                }

                return Ok(AuthUser {
                    user_id: api_key.user_id,
                    is_api_key: true,
                    scopes: api_key.scopes,
                });
            }

            // It's a JWT token
            let claims = auth_service
                .validate_token(&token)
                .map_err(|_| ErrorUnauthorized("Invalid token"))?;

            Ok(AuthUser {
                user_id: claims.sub,
                is_api_key: false,
                scopes: vec!["*".to_string()], // Session has all permissions
            })
        })
    }
}

/// Extract auth info from request
pub async fn extract_auth(
    req: &ServiceRequest,
    auth_service: &AuthService,
    store: &Store,
) -> Result<AuthUser, Error> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ErrorUnauthorized("Missing Authorization header"))?;

    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        // Check if it's an API key
        if token.starts_with("ts_") {
            let prefix = AuthService::get_api_key_prefix(token);
            let api_key = store
                .get_api_key_by_prefix(&prefix)
                .map_err(|_| ErrorUnauthorized("Invalid API key"))?;

            // Verify the full key
            if !auth_service
                .verify_password(token, &api_key.key_hash)
                .unwrap_or(false)
            {
                return Err(ErrorUnauthorized("Invalid API key"));
            }

            // Check expiration
            if let Some(expires_at) = api_key.expires_at {
                if expires_at < Utc::now() {
                    return Err(ErrorUnauthorized("API key expired"));
                }
            }

            return Ok(AuthUser {
                user_id: api_key.user_id,
                is_api_key: true,
                scopes: api_key.scopes,
            });
        }

        // It's a JWT token
        let claims = auth_service
            .validate_token(token)
            .map_err(|_| ErrorUnauthorized("Invalid token"))?;

        return Ok(AuthUser {
            user_id: claims.sub,
            is_api_key: false,
            scopes: vec!["*".to_string()], // Session has all permissions
        });
    }

    Err(ErrorUnauthorized("Invalid Authorization header format"))
}

/// Extract AuthUser from an HTTP request using AppState
pub fn extract_auth_from_request(
    req: &HttpRequest,
    auth_service: &AuthService,
) -> Result<AuthUser, actix_web::Error> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .ok_or_else(|| ErrorUnauthorized("Missing Authorization header"))?;

    if let Some(token) = auth_header.strip_prefix("Bearer ") {
        // Check if it's an API key (starts with ts_)
        if token.starts_with("ts_") {
            // For now, we don't support API key auth without store access
            // This would need to be refactored to pass store through
            return Err(ErrorUnauthorized("API key auth not implemented in this path"));
        }

        // It's a JWT token
        let claims = auth_service
            .validate_token(token)
            .map_err(|_| ErrorUnauthorized("Invalid token"))?;

        return Ok(AuthUser {
            user_id: claims.sub,
            is_api_key: false,
            scopes: vec!["*".to_string()], // Session has all permissions
        });
    }

    Err(ErrorUnauthorized("Invalid Authorization header format"))
}

/// Check if user has required scope
pub fn has_scope(auth_user: &AuthUser, required_scope: &str) -> bool {
    // Session tokens have all permissions
    if !auth_user.is_api_key || auth_user.scopes.contains(&"*".to_string()) {
        return true;
    }

    // Check for exact scope match
    if auth_user.scopes.contains(&required_scope.to_string()) {
        return true;
    }

    // Check for wildcard scope (e.g., "things:*" matches "things:read")
    let parts: Vec<&str> = required_scope.split(':').collect();
    if parts.len() == 2 {
        let wildcard = format!("{}:*", parts[0]);
        if auth_user.scopes.contains(&wildcard) {
            return true;
        }
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_auth_service() -> AuthService {
        let store = Store::in_memory().unwrap();
        AuthService::new("test_secret".to_string(), Arc::new(store))
    }

    #[test]
    fn test_password_hashing() {
        let auth = create_test_auth_service();
        let password = "my_secure_password";

        let hash = auth.hash_password(password).unwrap();
        assert!(auth.verify_password(password, &hash).unwrap());
        assert!(!auth.verify_password("wrong_password", &hash).unwrap());
    }

    #[test]
    fn test_jwt_token() {
        let auth = create_test_auth_service();
        let user_id = "user_123";

        let token = auth.generate_token(user_id).unwrap();
        let claims = auth.validate_token(&token).unwrap();

        assert_eq!(claims.sub, user_id);
        assert!(claims.exp > Utc::now().timestamp());
    }

    #[test]
    fn test_api_key_prefix() {
        let key = "ts_abc123def456";
        let prefix = AuthService::get_api_key_prefix(key);
        assert_eq!(prefix, "ts_abc123de");
    }

    #[test]
    fn test_scope_checking() {
        let user_with_read = AuthUser {
            user_id: "user_1".to_string(),
            is_api_key: true,
            scopes: vec!["things:read".to_string()],
        };

        assert!(has_scope(&user_with_read, "things:read"));
        assert!(!has_scope(&user_with_read, "things:write"));

        let user_with_wildcard = AuthUser {
            user_id: "user_2".to_string(),
            is_api_key: true,
            scopes: vec!["things:*".to_string()],
        };

        assert!(has_scope(&user_with_wildcard, "things:read"));
        assert!(has_scope(&user_with_wildcard, "things:write"));
        assert!(!has_scope(&user_with_wildcard, "kinds:read"));

        let session_user = AuthUser {
            user_id: "user_3".to_string(),
            is_api_key: false,
            scopes: vec![],
        };

        // Session users have all permissions
        assert!(has_scope(&session_user, "things:read"));
        assert!(has_scope(&session_user, "things:write"));
        assert!(has_scope(&session_user, "kinds:read"));
    }
}
