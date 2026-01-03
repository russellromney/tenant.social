# Tenant MCP Server

An MCP (Model Context Protocol) server that exposes Tenant functionality to AI assistants like Claude. This enables creating, searching, and managing Things directly from AI conversations.

## Features

**Tools (Actions)**
- `tenant_create_thing` - Create notes, links, tasks, or any custom Kind
- `tenant_search` - Full-text search across all Things
- `tenant_get_thing` - Retrieve a specific Thing by ID
- `tenant_update_thing` - Modify content, visibility, or metadata
- `tenant_delete_thing` - Delete a Thing (use with caution)
- `tenant_list_recent` - Get recent Things for context
- `tenant_add_tag` - Tag a Thing for organization
- `tenant_list_kinds` - See available Kinds
- `tenant_list_tags` - See all tags
- `tenant_create_link` - Create relationships between Things

**Resources (Context)**
- `tenant://things/recent` - Last 20 Things
- `tenant://kinds` - Available Kinds
- `tenant://tags` - All tags

## Installation

### Prerequisites
- Node.js 18+
- A running Tenant instance
- A Tenant API key with appropriate scopes

### Install Dependencies

```bash
cd mcp-server
npm install
npm run build
```

## Configuration

The MCP server requires two environment variables:

| Variable | Description | Example |
|----------|-------------|---------|
| `TENANT_URL` | Base URL of your Tenant instance | `https://you.tenant.social` or `http://localhost:8069` |
| `TENANT_API_KEY` | API key with required scopes | `tk_abc123...` |

### Creating an API Key

1. Log into your Tenant instance
2. Go to Settings → API Keys
3. Create a new key with these scopes:
   - `things:read` - Required for search and retrieval
   - `things:write` - Required for creating/updating
   - `things:delete` - Required for deletion (optional)
   - `kinds:read` - Required for listing Kinds
   - `reactions:write` - Optional, for adding reactions

4. Copy the key (it won't be shown again)

### Recommended Scopes for Full Functionality

```
things:read, things:write, things:delete, kinds:read
```

For read-only access (safer):
```
things:read, kinds:read
```

## Usage with Claude Desktop

Add to your Claude Desktop configuration (`~/Library/Application Support/Claude/claude_desktop_config.json` on macOS):

```json
{
  "mcpServers": {
    "tenant": {
      "command": "node",
      "args": ["/path/to/tenant.social/mcp-server/dist/index.js"],
      "env": {
        "TENANT_URL": "https://you.tenant.social",
        "TENANT_API_KEY": "tk_your_api_key_here"
      }
    }
  }
}
```

### Using npx (after publishing)

```json
{
  "mcpServers": {
    "tenant": {
      "command": "npx",
      "args": ["@tenant/mcp-server"],
      "env": {
        "TENANT_URL": "https://you.tenant.social",
        "TENANT_API_KEY": "tk_your_api_key_here"
      }
    }
  }
}
```

## Usage with Claude Code

Add to your Claude Code MCP settings (`.claude/settings.json` or global settings):

```json
{
  "mcpServers": {
    "tenant": {
      "command": "node",
      "args": ["/path/to/tenant.social/mcp-server/dist/index.js"],
      "env": {
        "TENANT_URL": "https://you.tenant.social",
        "TENANT_API_KEY": "tk_your_api_key_here"
      }
    }
  }
}
```

## Example Conversations

### Creating a Note
> "Save a note about the API design decisions we just discussed"
>
> Claude uses `tenant_create_thing` with type="note"

### Finding Context
> "What have I written about authentication?"
>
> Claude uses `tenant_search` with query="authentication"

### Managing Tasks
> "Create a task to review the PR tomorrow"
>
> Claude uses `tenant_create_thing` with type="task", metadata={ done: false }

> "Mark my 'review PR' task as done"
>
> Claude uses `tenant_search` to find the task, then `tenant_update_thing` with metadata={ done: true }

### Linking Things
> "Link this note to my project planning document"
>
> Claude uses `tenant_create_link` to connect the two Things

## Deployment Options

### Option 1: Local Development

Run alongside your local Tenant instance:

```bash
TENANT_URL=http://localhost:8069 \
TENANT_API_KEY=tk_your_key \
npm run dev
```

### Option 2: Global npm Install

```bash
npm install -g @tenant/mcp-server

# Then run from anywhere
TENANT_URL=https://you.tenant.social \
TENANT_API_KEY=tk_your_key \
tenant-mcp
```

### Option 3: Docker (for remote deployments)

```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --production
COPY dist ./dist
CMD ["node", "dist/index.js"]
```

```bash
docker build -t tenant-mcp .
docker run -e TENANT_URL=https://you.tenant.social \
           -e TENANT_API_KEY=tk_your_key \
           tenant-mcp
```

## Security Considerations

### API Key Security

1. **Never commit API keys** to version control
2. **Use environment variables** or secure secret management
3. **Limit scopes** to only what's needed
4. **Rotate keys** periodically
5. **Monitor usage** via the API key's last_used_at field

### Network Security

- The MCP server runs locally and communicates with your Tenant instance
- All API calls use the Bearer token in the Authorization header
- For remote Tenant instances, ensure HTTPS is used

### Recommended Setup

For personal use:
- Run MCP server locally
- Connect to your hosted Tenant instance over HTTPS
- Use a dedicated API key for the MCP server

## Troubleshooting

### "TENANT_API_KEY environment variable is required"

Set the environment variable before running:
```bash
export TENANT_API_KEY=tk_your_key
```

### "Tenant API error: 401"

Your API key is invalid or expired. Create a new one in Settings → API Keys.

### "Tenant API error: 403"

Your API key doesn't have the required scopes. Check the key's scopes match the operations you're attempting.

### Tools not appearing in Claude

1. Restart Claude Desktop/Claude Code after config changes
2. Check the MCP server logs for errors
3. Verify the path to `dist/index.js` is correct
4. Ensure `npm run build` completed successfully

## Development

### Running in Development Mode

```bash
npm run dev
```

### Type Checking

```bash
npm run typecheck
```

### Building

```bash
npm run build
```

## Future: Native Rust Integration

The MCP server could potentially be integrated directly into `tenant-vm` (the Rust backend). This would:

- Eliminate the separate Node.js process
- Reduce deployment complexity
- Use existing authentication (no separate API key needed)
- Enable WebSocket-based MCP transport

See [NATIVE_MCP.md](../docs/NATIVE_MCP.md) for the design proposal.

## License

MIT
