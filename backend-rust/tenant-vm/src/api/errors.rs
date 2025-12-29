//! Standardized API error responses
//!
//! Provides consistent error format across all API endpoints:
//! ```json
//! {"error": {"code": "not_found", "message": "Thing abc123 not found", "field": null}}
//! ```

use actix_web::{HttpResponse, ResponseError};
use serde::Serialize;
use std::fmt;
use utoipa::ToSchema;

use crate::store::StoreError;

/// Standardized API error type
#[derive(Debug, ToSchema)]
pub enum ApiError {
    /// Resource not found (404)
    NotFound {
        resource: String,
        id: Option<String>,
    },
    /// Validation error (400)
    Validation {
        message: String,
        field: Option<String>,
    },
    /// Authentication required (401)
    Unauthorized {
        message: String,
    },
    /// Permission denied (403)
    Forbidden {
        message: String,
        scope: Option<String>,
    },
    /// Internal server error (500)
    Internal {
        message: String,
    },
    /// Bad request (400)
    BadRequest {
        message: String,
    },
}

/// JSON error response body
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: ErrorBody,
}

/// Inner error body with code, message, and optional field
#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorBody {
    pub code: String,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
}

impl ApiError {
    /// Create a not found error
    pub fn not_found(resource: impl Into<String>) -> Self {
        ApiError::NotFound {
            resource: resource.into(),
            id: None,
        }
    }

    /// Create a not found error with ID
    pub fn not_found_with_id(resource: impl Into<String>, id: impl Into<String>) -> Self {
        ApiError::NotFound {
            resource: resource.into(),
            id: Some(id.into()),
        }
    }

    /// Create a validation error
    pub fn validation(message: impl Into<String>) -> Self {
        ApiError::Validation {
            message: message.into(),
            field: None,
        }
    }

    /// Create a validation error with field
    pub fn validation_field(field: impl Into<String>, message: impl Into<String>) -> Self {
        ApiError::Validation {
            message: message.into(),
            field: Some(field.into()),
        }
    }

    /// Create an unauthorized error
    pub fn unauthorized(message: impl Into<String>) -> Self {
        ApiError::Unauthorized {
            message: message.into(),
        }
    }

    /// Create a forbidden error
    pub fn forbidden(message: impl Into<String>) -> Self {
        ApiError::Forbidden {
            message: message.into(),
            scope: None,
        }
    }

    /// Create a forbidden error for missing scope
    pub fn missing_scope(scope: impl Into<String>) -> Self {
        let scope_str = scope.into();
        ApiError::Forbidden {
            message: format!("Missing required scope: {}", scope_str),
            scope: Some(scope_str),
        }
    }

    /// Create an internal error
    pub fn internal(message: impl Into<String>) -> Self {
        ApiError::Internal {
            message: message.into(),
        }
    }

    /// Create a bad request error
    pub fn bad_request(message: impl Into<String>) -> Self {
        ApiError::BadRequest {
            message: message.into(),
        }
    }

    /// Convert to error response
    fn to_response(&self) -> ErrorResponse {
        let (code, message, field) = match self {
            ApiError::NotFound { resource, id } => {
                let msg = match id {
                    Some(id) => format!("{} '{}' not found", resource, id),
                    None => format!("{} not found", resource),
                };
                ("not_found".to_string(), msg, None)
            }
            ApiError::Validation { message, field } => {
                ("validation_error".to_string(), message.clone(), field.clone())
            }
            ApiError::Unauthorized { message } => {
                ("unauthorized".to_string(), message.clone(), None)
            }
            ApiError::Forbidden { message, scope: _ } => {
                ("forbidden".to_string(), message.clone(), None)
            }
            ApiError::Internal { message } => {
                ("internal_error".to_string(), message.clone(), None)
            }
            ApiError::BadRequest { message } => {
                ("bad_request".to_string(), message.clone(), None)
            }
        };

        ErrorResponse {
            error: ErrorBody {
                code,
                message,
                field,
            },
        }
    }
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::NotFound { resource, id } => match id {
                Some(id) => write!(f, "{} '{}' not found", resource, id),
                None => write!(f, "{} not found", resource),
            },
            ApiError::Validation { message, .. } => write!(f, "Validation error: {}", message),
            ApiError::Unauthorized { message } => write!(f, "Unauthorized: {}", message),
            ApiError::Forbidden { message, .. } => write!(f, "Forbidden: {}", message),
            ApiError::Internal { message } => write!(f, "Internal error: {}", message),
            ApiError::BadRequest { message } => write!(f, "Bad request: {}", message),
        }
    }
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        let response = self.to_response();
        match self {
            ApiError::NotFound { .. } => HttpResponse::NotFound().json(response),
            ApiError::Validation { .. } => HttpResponse::BadRequest().json(response),
            ApiError::Unauthorized { .. } => HttpResponse::Unauthorized().json(response),
            ApiError::Forbidden { .. } => HttpResponse::Forbidden().json(response),
            ApiError::Internal { .. } => HttpResponse::InternalServerError().json(response),
            ApiError::BadRequest { .. } => HttpResponse::BadRequest().json(response),
        }
    }
}

/// Convert StoreError to ApiError
impl From<StoreError> for ApiError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::NotFound(resource) => ApiError::NotFound {
                resource,
                id: None,
            },
            StoreError::Database(e) => {
                log::error!("Database error: {:?}", e);
                ApiError::Internal {
                    message: "Database error".to_string(),
                }
            }
            StoreError::Json(e) => {
                log::error!("JSON error: {:?}", e);
                ApiError::Internal {
                    message: "Data serialization error".to_string(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_not_found_error() {
        let err = ApiError::not_found("Thing");
        let response = err.to_response();
        assert_eq!(response.error.code, "not_found");
        assert_eq!(response.error.message, "Thing not found");
        assert!(response.error.field.is_none());
    }

    #[test]
    fn test_not_found_with_id() {
        let err = ApiError::not_found_with_id("Thing", "abc123");
        let response = err.to_response();
        assert_eq!(response.error.code, "not_found");
        assert_eq!(response.error.message, "Thing 'abc123' not found");
    }

    #[test]
    fn test_validation_error_with_field() {
        let err = ApiError::validation_field("email", "Invalid email format");
        let response = err.to_response();
        assert_eq!(response.error.code, "validation_error");
        assert_eq!(response.error.message, "Invalid email format");
        assert_eq!(response.error.field, Some("email".to_string()));
    }

    #[test]
    fn test_missing_scope() {
        let err = ApiError::missing_scope("webhooks:write");
        let response = err.to_response();
        assert_eq!(response.error.code, "forbidden");
        assert!(response.error.message.contains("webhooks:write"));
    }
}
