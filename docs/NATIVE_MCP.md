# Native MCP Integration in tenant-vm

This document explores integrating MCP (Model Context Protocol) directly into the Rust backend (`tenant-vm`) instead of running a separate TypeScript server.

## Why Native Integration?

| Aspect | TypeScript MCP | Native Rust MCP |
|--------|----------------|-----------------|
| Deployment | Separate process needed | Single binary |
| Auth | Requires API key setup | Uses existing session/auth |
| Latency | HTTP round-trips | Direct database access |
| Memory | Node.js overhead | Minimal |
| Maintenance | Two codebases | One codebase |

## MCP Protocol Overview

MCP is JSON-RPC 2.0 over various transports:
- **stdio** (standard for CLI tools)
- **HTTP/SSE** (for web integrations)
- **WebSocket** (for real-time)

The protocol defines:
1. **Tools** - Functions the AI can call
2. **Resources** - Data the AI can read
3. **Prompts** - Predefined prompt templates

## Implementation Options

### Option A: HTTP-based MCP Endpoint

Add an `/mcp` endpoint to tenant-vm that speaks MCP over HTTP:

```rust
// src/api/mcp.rs

use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
struct JsonRpcRequest {
    jsonrpc: String,
    id: Option<serde_json::Value>,
    method: String,
    params: Option<serde_json::Value>,
}

#[derive(Serialize)]
struct JsonRpcResponse {
    jsonrpc: String,
    id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<JsonRpcError>,
}

pub async fn mcp_handler(
    req: web::Json<JsonRpcRequest>,
    store: web::Data<Store>,
    user: AuthenticatedUser,
) -> HttpResponse {
    match req.method.as_str() {
        "tools/list" => list_tools(),
        "tools/call" => call_tool(&req.params, &store, &user).await,
        "resources/list" => list_resources(),
        "resources/read" => read_resource(&req.params, &store, &user).await,
        _ => method_not_found(),
    }
}
```

**Pros:**
- Uses existing actix-web infrastructure
- Leverages existing auth (session cookies or API keys)
- Easy to add

**Cons:**
- Not compatible with stdio-based MCP clients (Claude Desktop)
- Would need a local proxy for Claude Desktop

### Option B: stdio Binary Mode

Add a `--mcp` flag to tenant-vm that runs as an MCP server over stdio:

```rust
// src/main.rs

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.contains(&"--mcp".to_string()) {
        // Run as MCP server over stdio
        run_mcp_stdio().await;
    } else {
        // Run as HTTP server
        run_http_server().await;
    }
}

async fn run_mcp_stdio() {
    let stdin = tokio::io::stdin();
    let stdout = tokio::io::stdout();

    // Read JSON-RPC messages from stdin
    // Write responses to stdout
    // ...
}
```

**Pros:**
- Compatible with Claude Desktop out of the box
- Single binary for everything
- No network latency

**Cons:**
- Needs database path passed via env var
- Can't use existing HTTP auth (would need local-only mode)
- More complex implementation

### Option C: WebSocket MCP Endpoint

Add a `/mcp/ws` WebSocket endpoint:

```rust
// src/api/mcp_ws.rs

use actix_web::{web, HttpRequest, HttpResponse};
use actix_ws::Message;

pub async fn mcp_websocket(
    req: HttpRequest,
    stream: web::Payload,
    store: web::Data<Store>,
) -> Result<HttpResponse, actix_web::Error> {
    let (res, mut session, stream) = actix_ws::handle(&req, stream)?;

    actix_web::rt::spawn(async move {
        // Handle MCP messages over WebSocket
    });

    Ok(res)
}
```

**Pros:**
- Real-time bidirectional communication
- Can push updates to AI
- Web-native

**Cons:**
- Not compatible with current Claude Desktop (stdio only)
- More complex than HTTP

## Recommended Approach

### Phase 1: TypeScript MCP Server (Now)
Use the TypeScript implementation for immediate compatibility with Claude Desktop and Claude Code. This works today.

### Phase 2: HTTP MCP Endpoint (Soon)
Add `/api/mcp` endpoint to tenant-vm. This enables:
- Web-based AI integrations
- Custom AI clients
- Server-to-server MCP communication

### Phase 3: stdio Mode (Later)
Add `--mcp` flag for full Claude Desktop compatibility without separate process. Requires:
- Local-only authentication mode
- Database path configuration
- Proper stdio handling in Rust

## Implementation Sketch: HTTP MCP Endpoint

```rust
// Add to src/api/mod.rs

mod mcp;

// In configure_routes:
.service(
    web::resource("/api/mcp")
        .route(web::post().to(mcp::handle_mcp_request))
)

// src/api/mcp.rs

use crate::models::*;
use crate::store::Store;
use actix_web::{web, HttpResponse};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[derive(Deserialize)]
pub struct McpRequest {
    jsonrpc: String,
    id: serde_json::Value,
    method: String,
    params: Option<serde_json::Value>,
}

#[derive(Serialize)]
pub struct McpResponse {
    jsonrpc: String,
    id: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<McpError>,
}

#[derive(Serialize)]
pub struct McpError {
    code: i32,
    message: String,
}

pub async fn handle_mcp_request(
    req: web::Json<McpRequest>,
    store: web::Data<Store>,
    user_id: web::ReqData<String>,
) -> HttpResponse {
    let result = match req.method.as_str() {
        "initialize" => handle_initialize(),
        "tools/list" => handle_list_tools(),
        "tools/call" => handle_call_tool(&req.params, &store, &user_id).await,
        "resources/list" => handle_list_resources(),
        "resources/read" => handle_read_resource(&req.params, &store, &user_id).await,
        _ => Err(McpError { code: -32601, message: "Method not found".into() }),
    };

    let response = match result {
        Ok(data) => McpResponse {
            jsonrpc: "2.0".into(),
            id: req.id.clone(),
            result: Some(data),
            error: None,
        },
        Err(e) => McpResponse {
            jsonrpc: "2.0".into(),
            id: req.id.clone(),
            result: None,
            error: Some(e),
        },
    };

    HttpResponse::Ok().json(response)
}

fn handle_initialize() -> Result<serde_json::Value, McpError> {
    Ok(json!({
        "protocolVersion": "2024-11-05",
        "capabilities": {
            "tools": {},
            "resources": {}
        },
        "serverInfo": {
            "name": "tenant",
            "version": env!("CARGO_PKG_VERSION")
        }
    }))
}

fn handle_list_tools() -> Result<serde_json::Value, McpError> {
    Ok(json!({
        "tools": [
            {
                "name": "tenant_create_thing",
                "description": "Create a new Thing in Tenant",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "content": { "type": "string" },
                        "type": { "type": "string", "default": "note" },
                        "visibility": { "type": "string", "enum": ["private", "friends", "public"] }
                    },
                    "required": ["content"]
                }
            },
            {
                "name": "tenant_search",
                "description": "Search for Things",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": { "type": "string" }
                    },
                    "required": ["query"]
                }
            }
            // ... more tools
        ]
    }))
}

async fn handle_call_tool(
    params: &Option<serde_json::Value>,
    store: &Store,
    user_id: &str,
) -> Result<serde_json::Value, McpError> {
    let params = params.as_ref()
        .ok_or(McpError { code: -32602, message: "Missing params".into() })?;

    let tool_name = params.get("name")
        .and_then(|v| v.as_str())
        .ok_or(McpError { code: -32602, message: "Missing tool name".into() })?;

    let arguments = params.get("arguments");

    match tool_name {
        "tenant_create_thing" => {
            let content = arguments
                .and_then(|a| a.get("content"))
                .and_then(|v| v.as_str())
                .ok_or(McpError { code: -32602, message: "Missing content".into() })?;

            let thing_type = arguments
                .and_then(|a| a.get("type"))
                .and_then(|v| v.as_str())
                .unwrap_or("note");

            let visibility = arguments
                .and_then(|a| a.get("visibility"))
                .and_then(|v| v.as_str())
                .unwrap_or("private");

            // Create the thing using existing store methods
            let thing = store.create_thing(
                user_id,
                thing_type,
                content,
                &std::collections::HashMap::new(),
                visibility,
            ).map_err(|e| McpError {
                code: -32000,
                message: e.to_string()
            })?;

            Ok(json!({
                "content": [{
                    "type": "text",
                    "text": format!("Created {} with ID: {}", thing_type, thing.id)
                }]
            }))
        }
        "tenant_search" => {
            let query = arguments
                .and_then(|a| a.get("query"))
                .and_then(|v| v.as_str())
                .ok_or(McpError { code: -32602, message: "Missing query".into() })?;

            let things = store.search_things(user_id, query, 20)
                .map_err(|e| McpError { code: -32000, message: e.to_string() })?;

            let formatted: Vec<String> = things.iter()
                .map(|t| format!("- [{}] {}: {}", t.thing_type, &t.id[..8], &t.content[..80.min(t.content.len())]))
                .collect();

            Ok(json!({
                "content": [{
                    "type": "text",
                    "text": format!("Found {} Things:\n{}", things.len(), formatted.join("\n"))
                }]
            }))
        }
        _ => Err(McpError { code: -32601, message: format!("Unknown tool: {}", tool_name) })
    }
}

fn handle_list_resources() -> Result<serde_json::Value, McpError> {
    Ok(json!({
        "resources": [
            {
                "uri": "tenant://things/recent",
                "name": "Recent Things",
                "mimeType": "application/json"
            },
            {
                "uri": "tenant://kinds",
                "name": "Available Kinds",
                "mimeType": "application/json"
            }
        ]
    }))
}

async fn handle_read_resource(
    params: &Option<serde_json::Value>,
    store: &Store,
    user_id: &str,
) -> Result<serde_json::Value, McpError> {
    let uri = params.as_ref()
        .and_then(|p| p.get("uri"))
        .and_then(|v| v.as_str())
        .ok_or(McpError { code: -32602, message: "Missing uri".into() })?;

    match uri {
        "tenant://things/recent" => {
            let things = store.get_things(user_id, None, None, None, 20, 0)
                .map_err(|e| McpError { code: -32000, message: e.to_string() })?;

            Ok(json!({
                "contents": [{
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": serde_json::to_string_pretty(&things).unwrap()
                }]
            }))
        }
        "tenant://kinds" => {
            let kinds = store.get_kinds(user_id)
                .map_err(|e| McpError { code: -32000, message: e.to_string() })?;

            Ok(json!({
                "contents": [{
                    "uri": uri,
                    "mimeType": "application/json",
                    "text": serde_json::to_string_pretty(&kinds).unwrap()
                }]
            }))
        }
        _ => Err(McpError { code: -32002, message: format!("Unknown resource: {}", uri) })
    }
}
```

## Connecting HTTP MCP to Claude Desktop

Since Claude Desktop expects stdio, you'd need a thin adapter:

```bash
#!/bin/bash
# mcp-http-adapter.sh
# Bridges stdio to HTTP MCP endpoint

TENANT_URL="${TENANT_URL:-http://localhost:8069}"
TENANT_API_KEY="${TENANT_API_KEY}"

while IFS= read -r line; do
    response=$(echo "$line" | curl -s -X POST \
        -H "Content-Type: application/json" \
        -H "Authorization: Bearer $TENANT_API_KEY" \
        -d @- \
        "$TENANT_URL/api/mcp")
    echo "$response"
done
```

Or use the TypeScript MCP server, which handles this natively.

## Conclusion

The recommended path:

1. **Now**: Use TypeScript MCP server (already built)
2. **Soon**: Add HTTP `/api/mcp` endpoint for web integrations
3. **Later**: Add `--mcp` stdio mode for single-binary deployment

The TypeScript server provides immediate value while we design the native integration. The HTTP endpoint opens up web-based AI integrations. The stdio mode achieves the "single binary" goal but requires more careful design around authentication.
