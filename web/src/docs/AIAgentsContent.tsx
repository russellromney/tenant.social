import { Theme } from '../theme'

export function AIAgentsContent({ theme }: { theme: Theme }) {
  return (
    <div style={{ lineHeight: 1.7, color: theme.textSecondary }}>
      <p style={{ marginBottom: 24 }}>
        This guide helps AI agents interact with Tenant's API to manage data programmatically.
      </p>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Core Concepts</h3>
      <p><strong>Things</strong> are the fundamental data unit in Tenant. Each Thing has:</p>
      <ul style={{ marginTop: 16, paddingLeft: 24 }}>
        <li><strong>type</strong> — String identifier (e.g., "note", "task", "bookmark", "gallery")</li>
        <li><strong>content</strong> — Main text/markdown content</li>
        <li><strong>visibility</strong> — "private", "friends", or "public" (defaults to "private")</li>
        <li><strong>metadata</strong> — JSON object for custom fields</li>
        <li><strong>photos</strong> — Array of photo objects (for galleries)</li>
      </ul>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Authentication</h3>
      <p>Use API keys with Bearer token authentication. Users create keys in Settings with specific scopes.</p>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`Authorization: Bearer ts_your_api_key_here`}
      </pre>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Common Operations</h3>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Create a Note</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`POST /api/things
Content-Type: application/json

{
  "type": "note",
  "content": "Meeting notes from today...",
  "visibility": "private",
  "metadata": {
    "tags": ["work", "meeting"]
  }
}`}
      </pre>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>List Things</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`GET /api/things?type=note&limit=20&offset=0`}
      </pre>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Search Things</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`GET /api/things/search?q=meeting+notes`}
      </pre>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Update a Thing</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`PUT /api/things/:id
Content-Type: application/json

{
  "content": "Updated content...",
  "visibility": "public"
}`}
      </pre>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Working with Photos</h3>
      <p>Galleries are Things with type="gallery" that contain photos. Photos are separate objects linked to the gallery Thing.</p>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Create a Gallery</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`POST /api/things
Content-Type: application/json

{
  "type": "gallery",
  "content": "Summer vacation photos",
  "visibility": "public",
  "metadata": {
    "photoCount": 3
  }
}`}
      </pre>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Upload Photos to Gallery</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`POST /api/things/:galleryId/photos
Content-Type: multipart/form-data

file: <binary image data>
caption: "Beach sunset"
order_index: 0`}
      </pre>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Social Features</h3>
      <p>Tenant supports following other users and visibility controls.</p>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Visibility Levels</h4>
      <ul style={{ paddingLeft: 24 }}>
        <li><strong>private</strong> — Only you can see it (default)</li>
        <li><strong>friends</strong> — Visible to users who follow you</li>
        <li><strong>public</strong> — Visible to anyone</li>
      </ul>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Follow a User</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`POST /api/friends
Content-Type: application/json

{
  "user_id": "target-user-uuid"
}`}
      </pre>

      <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Get Friend Feed</h4>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`GET /api/feed/friends?limit=20&offset=0`}
      </pre>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Best Practices</h3>
      <ul style={{ paddingLeft: 24 }}>
        <li><strong>Pagination</strong> — Use limit/offset params for large datasets</li>
        <li><strong>Visibility</strong> — Always set explicit visibility; defaults to "private"</li>
        <li><strong>Error Handling</strong> — Check HTTP status codes (200=success, 401=unauthorized, 404=not found)</li>
        <li><strong>Rate Limits</strong> — Be respectful; the API is designed for personal use</li>
        <li><strong>Metadata</strong> — Use for custom fields and tags; it's a flexible JSON object</li>
      </ul>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Response Format</h3>
      <p>All Thing objects return with this structure:</p>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`{
  "id": "abc123",
  "userId": "user456",
  "type": "note",
  "content": "Hello world",
  "visibility": "private",
  "metadata": {},
  "photos": [],
  "createdAt": "2024-01-15T10:30:00Z",
  "updatedAt": "2024-01-15T10:30:00Z"
}`}
      </pre>
    </div>
  )
}
