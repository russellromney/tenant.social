import { Theme } from '../theme'

export function APIDocsContent({ theme }: { theme: Theme }) {
  return (
    <div style={{ lineHeight: 1.7, color: theme.textSecondary }}>
      <p style={{ marginBottom: 24 }}>
        Tenant has a full REST API for building integrations. Create an API key in the settings to get started.
      </p>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Authentication</h3>
      <p>Use your API key in the Authorization header:</p>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`curl https://your-tenant.fly.dev/api/things \\
  -H "Authorization: Bearer ts_your_api_key"`}
      </pre>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>API Scopes</h3>
      <ul style={{ paddingLeft: 24 }}>
        <li><code style={{ background: theme.bgMuted, padding: '2px 6px', borderRadius: 4 }}>things:read</code> — Read things</li>
        <li><code style={{ background: theme.bgMuted, padding: '2px 6px', borderRadius: 4 }}>things:write</code> — Create and update things</li>
        <li><code style={{ background: theme.bgMuted, padding: '2px 6px', borderRadius: 4 }}>things:delete</code> — Delete things</li>
        <li><code style={{ background: theme.bgMuted, padding: '2px 6px', borderRadius: 4 }}>kinds:read</code> — Read kinds</li>
        <li><code style={{ background: theme.bgMuted, padding: '2px 6px', borderRadius: 4 }}>kinds:write</code> — Create and update kinds</li>
        <li><code style={{ background: theme.bgMuted, padding: '2px 6px', borderRadius: 4 }}>kinds:delete</code> — Delete kinds</li>
        <li><code style={{ background: theme.bgMuted, padding: '2px 6px', borderRadius: 4 }}>keys:manage</code> — Manage API keys</li>
      </ul>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Endpoints</h3>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>API Keys</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`GET    /api/keys           # List your API keys
POST   /api/keys            # Create new API key
GET    /api/keys/:id        # Get specific key
PUT    /api/keys/:id        # Update key (name, scopes)
DELETE /api/keys/:id        # Revoke API key`}
      </pre>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Things</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`GET    /api/things                      # List things (supports ?limit=50&offset=0&type=note)
GET    /api/things/:id                   # Get a specific thing
POST   /api/things                       # Create a thing
PUT    /api/things/:id                   # Update a thing
DELETE /api/things/:id                   # Delete a thing
POST   /api/things/:id/restore           # Restore soft-deleted thing
GET    /api/things/search?q=query        # Search things by content
GET    /api/things/:id/versions          # List all versions of a thing
GET    /api/things/:id/versions/:version # Get specific version
POST   /api/things/:id/versions/:version/revert # Revert to version
GET    /api/things/:id/backlinks         # Get things that link to this thing
POST   /api/things/bulk                  # Bulk create things
PUT    /api/things/bulk                  # Bulk update things
DELETE /api/things/bulk                  # Bulk delete things`}
      </pre>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Photos</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`POST   /api/upload          # Upload photo to gallery thing
GET    /api/photos/:id       # Get photo data
PUT    /api/photos/:id       # Update photo (caption, order_index)
DELETE /api/photos/:id       # Delete photo`}
      </pre>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Kinds</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`GET    /api/kinds           # List all kinds
GET    /api/kinds/:id        # Get a kind
POST   /api/kinds            # Create a kind
PUT    /api/kinds/:id        # Update a kind
DELETE /api/kinds/:id        # Delete a kind`}
      </pre>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Tags, Views, Export/Import</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`GET    /api/tags            # List tags
POST   /api/tags             # Create tag
GET    /api/views            # List views
POST   /api/views            # Create view
GET    /api/export           # Export all your data as JSON
POST   /api/import           # Import data from JSON`}
      </pre>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Social / Follows</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`POST   /api/friends                  # Follow a user
DELETE /api/follows/:user_id         # Unfollow a user
GET    /api/follows/followers        # List your followers
GET    /api/follows/following        # List users you follow
GET    /api/follows/mutuals          # List mutual follows
GET    /api/feed/friends             # Get friend feed (things from followed users)`}
      </pre>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Public Endpoints</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`GET    /api/public/profile          # Get owner's public profile
GET    /api/public/things            # Get owner's public things
GET    /api/fed/things/:user_id      # Federation: get friend-visible things`}
      </pre>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Example: Create a Thing</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`curl -X POST https://your-tenant.fly.dev/api/things \\
  -H "Authorization: Bearer ts_your_api_key" \\
  -H "Content-Type: application/json" \\
  -d '{
    "type": "note",
    "content": "Hello from the API!",
    "metadata": {}
  }'`}
      </pre>
    </div>
  )
}
