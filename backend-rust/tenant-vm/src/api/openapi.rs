//! OpenAPI specification for the Tenant VM API
//!
//! This module provides automatic OpenAPI documentation generation
//! using utoipa. Access the spec at `/api/openapi.json` and
//! interactive docs at `/api/docs/`.

use utoipa::OpenApi;

use crate::api::errors::{ApiError, ErrorBody, ErrorResponse};
use crate::models::{ApiKey, Attribute, Kind, Photo, Source, Subscription, Thing, User};
use crate::store::ThingQueryResult;

/// OpenAPI documentation struct
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Tenant VM API",
        version = "1.0.0",
        description = "Ultra-lightweight personal data API. Everything is a Thing.",
        license(name = "MIT")
    ),
    servers(
        (url = "/", description = "Current server")
    ),
    tags(
        (name = "things", description = "CRUD operations for Things"),
        (name = "kinds", description = "Thing type definitions"),
        (name = "auth", description = "Authentication endpoints"),
        (name = "webhooks", description = "Webhook subscription management"),
        (name = "api-keys", description = "API key management")
    ),
    components(
        schemas(
            Thing, Source, Photo, Kind, Attribute, ApiKey, Subscription, User,
            ThingQueryResult, ApiError, ErrorResponse, ErrorBody
        )
    )
)]
pub struct ApiDoc;
