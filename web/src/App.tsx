import { useState, useEffect } from 'preact/hooks'
import { EMOJI_CATEGORIES, ALL_EMOJIS } from './emojis'
import { useTheme, Theme } from './theme.tsx'
import { Markdown } from './Markdown.tsx'
import { PublicHomePage } from './PublicHomePage.tsx'
import { apiUrl, getRoute, navigateTo, routeHref, setupClientSideNavigation } from './api'

// Setup client-side navigation for SPA routing
setupClientSideNavigation()

// Types
interface Attribute {
  name: string
  type: string
  required: boolean
  options: string // comma-separated for select type
}

interface Kind {
  id: string
  name: string
  icon: string  // Emoji
  template: 'default' | 'compact' | 'card' | 'checklist' | 'link' | 'photo'
  attributes: Attribute[]
  commentable: boolean
  show_existing_comments: boolean
  reactable: boolean
  created_at: string
  updated_at: string
  isDefault?: boolean // for UI-only default kinds
}

// Available templates for display
const TEMPLATES = [
  { id: 'default', name: 'Default', description: 'Standard card with content and metadata' },
  { id: 'compact', name: 'Compact', description: 'Minimal one-line display' },
  { id: 'card', name: 'Card', description: 'Rich card with prominent content' },
  { id: 'checklist', name: 'Checklist', description: 'Task-style with checkbox' },
  { id: 'link', name: 'Link', description: 'URL-focused with clickable link' },
  { id: 'photo', name: 'Photo', description: 'Image/video gallery display' },
] as const

interface Photo {
  id: string
  thing_id: string
  caption: string
  order_index: number
  content_type: string
  filename: string
  size: number
  created_at: string
}

interface Thing {
  id: string
  type: string
  content: string
  metadata: Record<string, unknown>
  visibility: 'private' | 'friends' | 'public'
  created_at: string
  updated_at: string
  edited_at?: string | null
  photos?: Photo[]
  deleted_at?: string | null
  user_id?: string
  comment_count?: number
  top_replies?: Thing[]
}

// Reaction system types
interface ReactionSummary {
  counts: Record<string, number>
  user_reactions: string[]
}

interface EditHistoryEntry {
  id: string
  target_id: string
  target_type: 'thing' | 'comment'
  content: string
  edited_at: string
}

// Author info for comments
interface CommentAuthor {
  user_id: string
  username: string
  display_name: string
}

// Comment with author info (from API)
interface Comment extends Thing {
  metadata: {
    root_id: string
    parent_id: string
    depth: number
    [key: string]: unknown
  }
  // Enriched fields from API
  author?: CommentAuthor
  parent_content?: string
  parent_author?: CommentAuthor
}

interface Follow {
  id: string
  follower_id: string
  following_id: string
  remote_endpoint: string
  access_token: string | null
  created_at: string
  last_confirmed_at?: string | null
}

interface RemoteProfile {
  id: string
  username: string
  display_name: string
  bio: string
  avatar_url: string
}

interface FriendFeedItem extends Thing {
  owner_username?: string
  owner_endpoint?: string
}

// Default kinds - will be created in DB on first load
const DEFAULT_KINDS: Omit<Kind, 'created_at' | 'updated_at'>[] = [
  { id: 'default-post', name: 'post', icon: '💬', template: 'default', attributes: [], commentable: true, show_existing_comments: false, reactable: true, isDefault: true },
  { id: 'default-note', name: 'note', icon: '📝', template: 'default', attributes: [], commentable: false, show_existing_comments: false, reactable: false, isDefault: true },
  { id: 'default-link', name: 'link', icon: '🔗', template: 'link', attributes: [{ name: 'url', type: 'url', required: true, options: '' }], commentable: false, show_existing_comments: false, reactable: true, isDefault: true },
  { id: 'default-task', name: 'task', icon: '✅', template: 'checklist', attributes: [{ name: 'done', type: 'checkbox', required: false, options: '' }], commentable: false, show_existing_comments: false, reactable: false, isDefault: true },
  { id: 'default-photo', name: 'photo', icon: '📷', template: 'photo', attributes: [], commentable: false, show_existing_comments: false, reactable: true, isDefault: true },
  { id: 'default-gallery', name: 'gallery', icon: '🖼️', template: 'photo', attributes: [], commentable: false, show_existing_comments: false, reactable: true, isDefault: true },
]

// Path-based routing
function useRoute() {
  const [route, setRoute] = useState(getRoute())

  useEffect(() => {
    const handleRouteChange = () => setRoute(getRoute())
    window.addEventListener('popstate', handleRouteChange)
    return () => window.removeEventListener('popstate', handleRouteChange)
  }, [])

  return route
}

// Hook for detecting mobile screen size
function useIsMobile(breakpoint = 640) {
  const [isMobile, setIsMobile] = useState(window.innerWidth < breakpoint)

  useEffect(() => {
    const handleResize = () => setIsMobile(window.innerWidth < breakpoint)
    window.addEventListener('resize', handleResize)
    return () => window.removeEventListener('resize', handleResize)
  }, [breakpoint])

  return isMobile
}

// Auth status from the server
interface AuthStatus {
  hasOwner: boolean
  registrationEnabled: boolean
  sandboxMode: boolean
  authDisabled: boolean
}

// Shared Footer Component
function Footer({ theme }: { theme: Theme }) {
  return (
    <footer style={{
      marginTop: 48,
      paddingTop: 24,
      borderTop: `1px solid ${theme.border}`,
      textAlign: 'center',
      color: theme.textSubtle,
      fontSize: 14,
    }}>
      <div style={{ marginBottom: 8, color: theme.textMuted, fontSize: 13 }}>
        Your personal social data platform
      </div>
      <div style={{ marginBottom: 12 }}>
        <a href={routeHref('/docs')} style={{ color: theme.textMuted, textDecoration: 'none', margin: '0 12px' }}>About</a>
        <a href={routeHref('/docs/api')} style={{ color: theme.textMuted, textDecoration: 'none', margin: '0 12px' }}>API</a>
        <a href={routeHref('/docs/deployment')} style={{ color: theme.textMuted, textDecoration: 'none', margin: '0 12px' }}>Deploy</a>
        <a href="https://github.com/russellromney/tenant.social" target="_blank" rel="noopener noreferrer" style={{ color: theme.textMuted, textDecoration: 'none', margin: '0 12px' }}>GitHub</a>
      </div>
      Made with ❤️ in NYC by <a href="https://russellromney.com" target="_blank" rel="noopener noreferrer" style={{ color: theme.link, textDecoration: 'none' }}>me</a>
    </footer>
  )
}

// Content components for each documentation section
function AboutContent({ theme }: { theme: any }) {
  return (
    <div style={{ lineHeight: 1.7, color: theme.textSecondary }}>
      <p style={{ fontSize: 18, marginBottom: 24 }}>
        <strong>Tenant</strong> is your personal social data platform. Own your data, your way.
      </p>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>What is Tenant?</h3>
      <p>
        Tenant combines the best parts of Twitter and Notion—without the creepy parts.
        It's open source, highly extensible, and puts you in control.
      </p>

      <ul style={{ marginTop: 16, paddingLeft: 24 }}>
        <li><strong>Store anything</strong> — Notes, links, tasks, bookmarks, photos, anything</li>
        <li><strong>Your own schema</strong> — Define custom types (Kinds) with your own attributes</li>
        <li><strong>Social features</strong> — Follow other Tenant users, share with friends or publicly</li>
        <li><strong>API-first</strong> — Full REST API with granular scopes for integrations</li>
        <li><strong>Version history</strong> — Never lose data, track every change</li>
        <li><strong>Cheap to run</strong> — Single binary, SQLite or Turso, minimal resources</li>
      </ul>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Social Features</h3>
      <p>Tenant supports social interactions between instances:</p>
      <ul style={{ marginTop: 16, paddingLeft: 24 }}>
        <li><strong>Visibility</strong> — Mark things as private, friends-only, or public</li>
        <li><strong>Follow users</strong> — Follow other Tenant users to see their shared content</li>
        <li><strong>Friend feed</strong> — See things from people you follow in one place</li>
        <li><strong>Public profiles</strong> — Share your public things with anyone</li>
      </ul>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Philosophy</h3>
      <p>
        Social platforms have become creepy data extractors. Notion-like tools are great but don't feel social.
        Tenant is different:
      </p>
      <ul style={{ marginTop: 16, paddingLeft: 24 }}>
        <li><strong>Single tenant</strong> — One owner per instance. Your data, your server.</li>
        <li><strong>Open source</strong> — See exactly what's running. Modify it how you like.</li>
        <li><strong>Extensible</strong> — API keys with granular scopes let you build integrations</li>
        <li><strong>Not creepy</strong> — No ads, no tracking, no selling your data</li>
      </ul>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Links</h3>
      <ul style={{ paddingLeft: 24 }}>
        <li><a href="https://github.com/russellromney/tenant.social" style={{ color: theme.link }}>GitHub Repository</a></li>
        <li><a href="https://tenant.social" style={{ color: theme.link }}>Sandbox (try it out)</a></li>
      </ul>
    </div>
  )
}

function APIDocsContent({ theme }: { theme: any }) {
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

function DeploymentContent({ theme }: { theme: any }) {
  return (
    <div style={{ lineHeight: 1.7, color: theme.textSecondary }}>
      <p style={{ marginBottom: 24 }}>
        Deploy your own Tenant instance in minutes. Choose your preferred platform:
      </p>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Fly.io (Recommended)</h3>
      <p>Easiest deployment with automatic HTTPS and global edge network.</p>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`# Install Fly CLI
curl -L https://fly.io/install.sh | sh

# Clone and deploy
git clone https://github.com/russellromney/tenant.social.git
cd tenant.social

# Create app and volume
fly apps create my-tenant
fly volumes create tenant_data --size 1 --region ewr

# Deploy
fly deploy

# Visit https://my-tenant.fly.dev`}
      </pre>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Docker</h3>
      <p>Run anywhere Docker runs.</p>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`# Build
docker build -t tenant .

# Run with persistent data
docker run -d \\
  -p 8080:8080 \\
  -v tenant_data:/data \\
  -e PRODUCTION=true \\
  -e DB_BACKEND=sqlite \\
  -e SQLITE_PATH=/data/tenant.db \\
  tenant`}
      </pre>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Run Locally</h3>
      <p>For development or personal use on your machine.</p>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`# Clone
git clone https://github.com/russellromney/tenant.social.git
cd tenant.social

# Install frontend dependencies
cd web && npm install && cd ..

# Run (uses local SQLite)
make dev

# Visit http://localhost:3069`}
      </pre>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Turso (Cloud Database)</h3>
      <p>Use Turso for edge-replicated SQLite in the cloud.</p>
      <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`# Create Turso database
turso db create tenant

# Get credentials
turso db show tenant --url
turso db tokens create tenant

# Set environment variables
DB_BACKEND=turso
TURSO_DATABASE_URL=libsql://tenant-xxx.turso.io
TURSO_AUTH_TOKEN=your-token`}
      </pre>

      <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12, color: theme.text }}>Environment Variables</h3>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 14 }}>
        <thead>
          <tr style={{ borderBottom: `2px solid ${theme.borderInput}` }}>
            <th style={{ textAlign: 'left', padding: '8px 0' }}>Variable</th>
            <th style={{ textAlign: 'left', padding: '8px 0' }}>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr style={{ borderBottom: `1px solid ${theme.border}` }}>
            <td style={{ padding: '8px 0' }}><code>PORT</code></td>
            <td style={{ padding: '8px 0' }}>Server port (default: 8069)</td>
          </tr>
          <tr style={{ borderBottom: `1px solid ${theme.border}` }}>
            <td style={{ padding: '8px 0' }}><code>PRODUCTION</code></td>
            <td style={{ padding: '8px 0' }}>Set to "true" for production mode</td>
          </tr>
          <tr style={{ borderBottom: `1px solid ${theme.border}` }}>
            <td style={{ padding: '8px 0' }}><code>DB_BACKEND</code></td>
            <td style={{ padding: '8px 0' }}>"sqlite" or "turso"</td>
          </tr>
          <tr style={{ borderBottom: `1px solid ${theme.border}` }}>
            <td style={{ padding: '8px 0' }}><code>SQLITE_PATH</code></td>
            <td style={{ padding: '8px 0' }}>Path to SQLite database file</td>
          </tr>
          <tr style={{ borderBottom: `1px solid ${theme.border}` }}>
            <td style={{ padding: '8px 0' }}><code>TURSO_DATABASE_URL</code></td>
            <td style={{ padding: '8px 0' }}>Turso database URL</td>
          </tr>
          <tr>
            <td style={{ padding: '8px 0' }}><code>TURSO_AUTH_TOKEN</code></td>
            <td style={{ padding: '8px 0' }}>Turso auth token</td>
          </tr>
        </tbody>
      </table>
    </div>
  )
}

function AIAgentsContent({ theme }: { theme: any }) {
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

// Unified Documentation Page with Sidebar Navigation
function UnifiedDocsPage() {
  const { theme } = useTheme()
  const route = getRoute()

  // Determine which section to show based on route
  let section = 'about' // default
  if (route === '/about' || route === '/docs') section = 'about'
  else if (route === '/guides' || route.includes('/deployment')) section = 'deployment'
  else if (route.includes('/ai-agents')) section = 'ai-agents'
  else if (route.includes('/api')) section = 'api'

  const sections = [
    { id: 'about', label: 'About', route: routeHref('/docs') },
    { id: 'ai-agents', label: 'AI Agents', route: routeHref('/docs/ai-agents') },
    { id: 'api', label: 'API Reference', route: routeHref('/docs/api') },
    { id: 'deployment', label: 'Deployment', route: routeHref('/docs/deployment') },
  ]

  const sectionTitles: Record<string, string> = {
    'about': 'About Tenant',
    'ai-agents': 'AI Agent Guide',
    'api': 'API Documentation',
    'deployment': 'Deployment Guides',
  }

  return (
    <div style={{ display: 'flex', minHeight: '100vh', fontFamily: 'system-ui, sans-serif', background: theme.bg }}>
      {/* Sidebar */}
      <div style={{
        width: 220,
        background: theme.bgCard,
        borderRight: `1px solid ${theme.border}`,
        padding: '20px 0',
        position: 'fixed',
        height: '100vh',
        overflowY: 'auto',
      }}>
        <a href={routeHref('/')} style={{ textDecoration: 'none', color: theme.text, display: 'block', padding: '0 20px 20px' }}>
          <h1 style={{ fontSize: 24, fontWeight: 700, margin: 0 }}>tenant</h1>
        </a>
        <nav>
          {sections.map(s => (
            <a
              key={s.id}
              href={s.route}
              style={{
                display: 'block',
                padding: '10px 20px',
                color: section === s.id ? theme.accent : theme.textSecondary,
                textDecoration: 'none',
                background: section === s.id ? theme.bgMuted : 'transparent',
                borderLeft: section === s.id ? `3px solid ${theme.accent}` : '3px solid transparent',
                fontSize: 14,
                fontWeight: section === s.id ? 600 : 400,
              }}
            >
              {s.label}
            </a>
          ))}
        </nav>
      </div>

      {/* Main content */}
      <div style={{ marginLeft: 220, flex: 1 }}>
        <div style={{ maxWidth: 800, margin: '0 auto', padding: 40 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 32 }}>
            <h2 style={{ fontSize: 28, fontWeight: 600, margin: 0, color: theme.text }}>{sectionTitles[section]}</h2>
            <a
              href={routeHref('/')}
              style={{
                padding: '8px 16px',
                background: theme.bgHover,
                color: theme.textSecondary,
                borderRadius: 6,
                fontSize: 14,
                textDecoration: 'none',
              }}
            >
              ← Back
            </a>
          </div>

          {section === 'about' && <AboutContent theme={theme} />}
          {section === 'ai-agents' && <AIAgentsContent theme={theme} />}
          {section === 'api' && <APIDocsContent theme={theme} />}
          {section === 'deployment' && <DeploymentContent theme={theme} />}

          <Footer theme={theme} />
        </div>
      </div>
    </div>
  )
}

// Auth Screen Component - handles both login and registration
function AuthScreen({ onAuth, authStatus }: { onAuth: () => void, authStatus: AuthStatus | null }) {
  const { theme } = useTheme()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [username, setUsername] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  console.log('[AuthScreen] authStatus:', authStatus)
  console.log('[AuthScreen] authStatus?.sandboxMode:', authStatus?.sandboxMode)

  // Sandbox mode - show public home page
  if (authStatus?.sandboxMode) {
    console.log('[AuthScreen] Rendering public home page for sandbox mode');
    return <PublicHomePage theme={theme} onLogin={onAuth} />
  }


  async function handleSubmit(e: Event) {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      const endpoint = mode === 'register' ? '/api/auth/register' : '/api/auth/login'
      const body = mode === 'register'
        ? { username, email, password }
        : { username, password }

      console.log('Submitting to', endpoint, body)

      const res = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        credentials: 'include',
      })

      console.log('Response status:', res.status)

      if (res.ok) {
        onAuth()
      } else {
        const data = await res.json()
        console.log('Error response:', data)
        setError(data.error || 'Authentication failed')
      }
    } catch (err) {
      console.error('Network error:', err)
      setError('Network error')
    }
    setLoading(false)
  }

  const isValid = mode === 'register'
    ? username && email && password
    : username && password

  // Registration is only shown if explicitly enabled
  const showRegisterOption = authStatus?.registrationEnabled

  return (
    <div style={{
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      minHeight: '100vh',
      fontFamily: 'system-ui, sans-serif',
      background: theme.bg,
      flexDirection: 'column',
    }}>
      <div style={{
        background: theme.bgCard,
        padding: 32,
        borderRadius: 12,
        boxShadow: `0 4px 12px ${theme.shadow}`,
        width: '100%',
        maxWidth: 380,
      }}>
        <h1 style={{ fontSize: 36, fontWeight: 700, margin: '0 0 8px', textAlign: 'center', color: theme.text }}>tenant.social</h1>
        <p style={{ color: theme.textMuted, fontSize: 14, margin: '0 0 20px', textAlign: 'center' }}>
          your corner of the internet
        </p>
        <p style={{ color: theme.textSecondary, fontSize: 14, margin: '0 0 16px', textAlign: 'center', fontWeight: 500 }}>
          {mode === 'register' ? 'Create your account' : 'Sign in to continue'}
        </p>
        <form onSubmit={handleSubmit}>
          <input
            type="text"
            value={username}
            onInput={e => setUsername((e.target as HTMLInputElement).value)}
            placeholder="Username"
            autoFocus
            style={{
              width: '100%',
              padding: '12px 14px',
              border: `1px solid ${theme.borderInput}`,
              borderRadius: 6,
              fontSize: 16,
              boxSizing: 'border-box',
              marginBottom: 12,
              background: theme.bgInput,
              color: theme.text,
            }}
          />
          {mode === 'register' && (
            <input
              type="email"
              value={email}
              onInput={e => setEmail((e.target as HTMLInputElement).value)}
              placeholder="Email"
              style={{
                width: '100%',
                padding: '12px 14px',
                border: `1px solid ${theme.borderInput}`,
                borderRadius: 6,
                fontSize: 16,
                boxSizing: 'border-box',
                marginBottom: 12,
                background: theme.bgInput,
                color: theme.text,
              }}
            />
          )}
          <input
            type="password"
            value={password}
            onInput={e => setPassword((e.target as HTMLInputElement).value)}
            placeholder="Password"
            style={{
              width: '100%',
              padding: '12px 14px',
              border: error ? `1px solid ${theme.error}` : `1px solid ${theme.borderInput}`,
              borderRadius: 6,
              fontSize: 16,
              boxSizing: 'border-box',
              marginBottom: 12,
              background: theme.bgInput,
              color: theme.text,
            }}
          />
          {error && (
            <p style={{ color: theme.error, fontSize: 13, margin: '0 0 12px' }}>{error}</p>
          )}
          <button
            type="submit"
            disabled={!isValid || loading}
            style={{
              width: '100%',
              padding: '12px 20px',
              background: isValid && !loading ? theme.accent : theme.textDisabled,
              color: isValid && !loading ? theme.accentText : theme.textSubtle,
              border: 'none',
              borderRadius: 6,
              fontSize: 16,
              fontWeight: 600,
              cursor: isValid && !loading ? 'pointer' : 'not-allowed',
              marginBottom: 16,
            }}
          >
            {loading
              ? (mode === 'register' ? 'Creating account...' : 'Signing in...')
              : (mode === 'register' ? 'Create account' : 'Sign in')}
          </button>
        </form>
        {/* Only show toggle if registration is enabled */}
        {showRegisterOption && (
          <p style={{ textAlign: 'center', fontSize: 14, color: theme.textMuted, margin: 0 }}>
            {mode === 'register' ? (
              <>Already have an account? <button onClick={() => { setMode('login'); setError('') }} style={{ background: 'none', border: 'none', color: theme.link, cursor: 'pointer', fontSize: 14, padding: 0 }}>Sign in</button></>
            ) : (
              <>Don't have an account? <button onClick={() => { setMode('register'); setError('') }} style={{ background: 'none', border: 'none', color: theme.link, cursor: 'pointer', fontSize: 14, padding: 0 }}>Register</button></>
            )}
          </p>
        )}
        {/* For single-tenant instances, no registration option */}
        {!showRegisterOption && mode === 'login' && (
          <p style={{ textAlign: 'center', fontSize: 12, color: theme.textSubtle, margin: 0 }}>
            This is a private instance
          </p>
        )}
      </div>
      <Footer theme={theme} />
    </div>
  )
}

// Post detail page - shows a single post at its own URL
function PostPage({
  postId,
  kinds,
  theme,
  isDark,
  toggleTheme,
  onLogout,
  onBack,
  onDelete,
  isMobile,
}: {
  postId: string
  kinds: Kind[]
  theme: Theme
  isDark: boolean
  toggleTheme: () => void
  onLogout: () => void
  onBack: () => void
  onDelete: (id: string) => void
  isMobile: boolean
}) {
  const [thing, setThing] = useState<Thing | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [editingThing, setEditingThing] = useState<Thing | null>(null)
  const [backlinks, setBacklinks] = useState<Thing[]>([])
  const [backlinksLoading, setBacklinksLoading] = useState(false)

  useEffect(() => {
    fetchPost()
  }, [postId])

  async function fetchPost() {
    setLoading(true)
    try {
      const res = await fetch(apiUrl(`/api/things/${postId}`), { credentials: 'include' })
      if (res.ok) {
        const data = await res.json()
        setThing(data)
        await fetchBacklinks(data.id)
      } else {
        setError('Post not found')
      }
    } catch {
      setError('Failed to load post')
    } finally {
      setLoading(false)
    }
  }

  async function fetchBacklinks(thingId: string) {
    setBacklinksLoading(true)
    try {
      const res = await fetch(apiUrl(`/api/things/${thingId}/backlinks`), { credentials: 'include' })
      if (res.ok) {
        const data = await res.json()
        setBacklinks(data.backlinks || [])
      }
    } catch (err) {
      console.error('Failed to fetch backlinks:', err)
    } finally {
      setBacklinksLoading(false)
    }
  }

  function getKind(typeName: string): Kind | undefined {
    return kinds.find(k => k.name === typeName)
  }

  async function updateThing(updated: Thing) {
    try {
      const res = await fetch(apiUrl(`/api/things/${updated.id}`), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updated),
        credentials: 'include',
      })
      if (res.ok) {
        // Refetch to get fresh data with photos
        await fetchPost()
        setEditingThing(null)
      }
    } catch (err) {
      console.error('Failed to update thing:', err)
    }
  }

  const kind = thing ? getKind(thing.type) : undefined

  return (
    <div style={{ maxWidth: 700, margin: '0 auto', padding: isMobile ? 12 : 20, fontFamily: 'system-ui, sans-serif', background: theme.bg, minHeight: '100vh', color: theme.text }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: isMobile ? 16 : 24, gap: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <button
            onClick={onBack}
            style={{
              background: 'none',
              border: 'none',
              color: theme.textMuted,
              cursor: 'pointer',
              fontSize: 20,
              padding: '4px 8px',
            }}
          >
            ←
          </button>
          <a href={routeHref('/')} style={{ textDecoration: 'none', color: theme.text }}>
            <h1 style={{ fontSize: isMobile ? 22 : 28, fontWeight: 700, margin: 0 }}>tenant</h1>
          </a>
        </div>
        <div style={{ display: 'flex', gap: isMobile ? 4 : 8, alignItems: 'center' }}>
          <button
            onClick={toggleTheme}
            style={{
              padding: isMobile ? '6px 10px' : '8px 12px',
              background: theme.bgHover,
              color: theme.textMuted,
              border: 'none',
              borderRadius: 6,
              cursor: 'pointer',
              fontSize: 14,
            }}
          >
            {isDark ? '☀️' : '🌙'}
          </button>
          <button
            onClick={onLogout}
            style={{
              padding: isMobile ? '6px 10px' : '8px 12px',
              background: theme.bgHover,
              color: theme.textMuted,
              border: 'none',
              borderRadius: 6,
              cursor: 'pointer',
              fontSize: 14,
            }}
          >
            Logout
          </button>
        </div>
      </div>

      {/* Content */}
      {loading ? (
        <p style={{ textAlign: 'center', color: theme.textMuted }}>Loading...</p>
      ) : error ? (
        <p style={{ textAlign: 'center', color: theme.error }}>{error}</p>
      ) : thing ? (
        <>
          <ThingCard
            thing={thing}
            kind={kind}
            onEdit={() => setEditingThing(thing)}
            onDelete={() => {
              onDelete(thing.id)
              onBack()
            }}
            onUpdateThing={updateThing}
            theme={theme}
            isDetailView={true}
          />

          {/* Comments Section - only show if Kind allows it */}
          {(kind?.commentable || kind?.show_existing_comments) && (
            <CommentsSection
              thingId={thing.id}
              thingOwnerId={thing.user_id || null}
              theme={theme}
              commentable={kind?.commentable ?? false}
            />
          )}

          {/* Backlinks Section */}
          {!backlinksLoading && backlinks.length > 0 && (
            <div style={{ marginTop: 32, paddingTop: 24, borderTop: `1px solid ${theme.border}` }}>
              <h2 style={{ fontSize: 18, fontWeight: 600, marginTop: 0, marginBottom: 16, color: theme.text }}>
                Backlinks ({backlinks.length})
              </h2>
              <div style={{ display: 'grid', gridTemplateColumns: isMobile ? '1fr' : 'repeat(auto-fill, minmax(250px, 1fr))', gap: 12 }}>
                {backlinks.map(backlink => (
                  <ThingCard
                    key={backlink.id}
                    thing={backlink}
                    kind={getKind(backlink.type)}
                    onEdit={() => {}} // Not editing from backlinks view
                    onDelete={() => {}} // Not deleting from backlinks view
                    onUpdateThing={() => {}} // Not updating from backlinks view
                    theme={theme}
                    isDetailView={false}
                  />
                ))}
              </div>
            </div>
          )}
        </>
      ) : null}

      {/* Edit Modal */}
      {editingThing && (
        <EditThingModal
          thing={editingThing}
          kinds={kinds}
          onSave={updateThing}
          onClose={() => setEditingThing(null)}
          theme={theme}
        />
      )}

      <Footer theme={theme} />
    </div>
  )
}

function App() {
  const route = useRoute()
  const isMobile = useIsMobile()
  const { theme, isDark, toggleTheme } = useTheme()
  const [isAuthenticated, setIsAuthenticated] = useState<boolean | null>(null)
  const [authStatus, setAuthStatus] = useState<AuthStatus | null>(null)
  const [things, setThings] = useState<Thing[]>([])
  const [kinds, setKinds] = useState<Kind[]>([])
  const [newContent, setNewContent] = useState('')
  const [newType, setNewType] = useState('note')
  const [newMetadata, setNewMetadata] = useState<Record<string, unknown>>({})
  const [newVisibility, setNewVisibility] = useState<'private' | 'friends' | 'public'>('private')
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [filterKind, setFilterKind] = useState('')
  const [editingThing, setEditingThing] = useState<Thing | null>(null)
  const [editingKind, setEditingKind] = useState<Kind | null>(null)
  const [uploading, setUploading] = useState(false)
  const [defaultKindId, setDefaultKindId] = useState<string | null>(() => {
    try { return localStorage.getItem('defaultKindId') } catch { return null }
  })

  const isSettingsPage = route === '/settings' || route === '/data' || route === '/keys' || route === '/kinds' || route === '/friends' || route === '/integrations' // aliases
  const isFeedPage = route === '/feed'
  const isBookmarksPage = route === '/bookmarks'
  const isProfilePage = route === '/' || route === '' || route === '/profile'
  const isSubPage = isSettingsPage

  // Save defaultKindId to localStorage
  function handleSetDefaultKind(id: string | null) {
    setDefaultKindId(id)
    try {
      if (id) localStorage.setItem('defaultKindId', id)
      else localStorage.removeItem('defaultKindId')
    } catch {}
  }

  // Check authentication on mount
  useEffect(() => {
    checkAuth()
  }, [])

  // Restore scroll position when returning to feed from a post
  useEffect(() => {
    const isFeedRoute = route === '/' || route === ''
    if (isFeedRoute && !loading) {
      const savedPosition = sessionStorage.getItem('feedScrollPosition')
      if (savedPosition) {
        // Use requestAnimationFrame to ensure DOM is ready
        requestAnimationFrame(() => {
          window.scrollTo(0, parseInt(savedPosition, 10))
        })
        // Clear the saved position after restoring
        sessionStorage.removeItem('feedScrollPosition')
      }
    }
  }, [route, loading])

  async function checkAuth() {
    try {
      // First, check auth status to understand the instance state
      const statusRes = await fetch(apiUrl('/api/auth/status'), { credentials: 'include' })
      console.log('[checkAuth] /api/auth/status response:', statusRes.status)
      if (statusRes.ok) {
        const status: AuthStatus = await statusRes.json()
        console.log('[checkAuth] Auth status:', status)
        setAuthStatus(status)

        // In sandbox mode, check if already authenticated (after clicking Enter Sandbox)
        if (status.sandboxMode) {
          console.log('[checkAuth] Sandbox mode detected, checking for existing session')
          const res = await fetch(apiUrl('/api/auth/me'), { credentials: 'include' })
          if (res.ok) {
            console.log('[checkAuth] Sandbox session found, setting isAuthenticated=true')
            setIsAuthenticated(true)
          } else {
            console.log('[checkAuth] No sandbox session, showing Enter Sandbox button')
            setIsAuthenticated(false)
          }
          return
        }

        // In auth-disabled mode, show the welcome screen first (user clicks "Enter Sandbox")
        if (status.authDisabled) {
          console.log('[checkAuth] Auth disabled mode detected')
          setIsAuthenticated(false)
          return
        }
      }

      // Then check if we have a valid session
      console.log('[checkAuth] Checking /api/auth/me for session')
      const res = await fetch(apiUrl('/api/auth/me'), { credentials: 'include' })
      if (res.ok) {
        console.log('[checkAuth] Valid session found, setting isAuthenticated=true')
        setIsAuthenticated(true)
      } else {
        console.log('[checkAuth] No valid session, setting isAuthenticated=false')
        setIsAuthenticated(false)
      }
    } catch (err) {
      console.error('[checkAuth] Error:', err)
      setIsAuthenticated(false)
    }
  }

  async function handleLogout() {
    try {
      await fetch(apiUrl('/api/auth/logout'), {
        method: 'POST',
        credentials: 'include',
      })
    } catch {
      // Ignore errors, still log out locally
    }
    setIsAuthenticated(false)
  }

  // Get kinds sorted by frequency (most used first), excluding photo (handled separately)
  function getSortedKindsByFrequency(): Kind[] {
    const countByType: Record<string, number> = {}
    things.forEach(t => {
      countByType[t.type] = (countByType[t.type] || 0) + 1
    })
    return [...kinds]
      .filter(k => k.name !== 'photo') // Photo uploads handled separately
      .sort((a, b) => (countByType[b.name] || 0) - (countByType[a.name] || 0))
  }

  useEffect(() => {
    if (isAuthenticated) {
      setLoading(true)
      initializeKinds()
      fetchThings()
    }
  }, [isAuthenticated])

  // Set default Kind when kinds load or defaultKindId changes
  useEffect(() => {
    if (kinds.length === 0) return
    if (defaultKindId) {
      const defaultKind = kinds.find(k => k.id === defaultKindId)
      if (defaultKind) {
        setNewType(defaultKind.name)
        return
      }
    }
    // Fallback to first kind
    setNewType(kinds[0].name)
  }, [kinds, defaultKindId])

  useEffect(() => {
    if (!isAuthenticated) return
    if (searchQuery) {
      searchThings(searchQuery)
    } else {
      fetchThings()
    }
  }, [searchQuery, filterKind])

  // Reset metadata when type changes
  useEffect(() => {
    setNewMetadata({})
  }, [newType])

  // Listen for paste events for images
  useEffect(() => {
    window.addEventListener('paste', handlePaste)
    return () => window.removeEventListener('paste', handlePaste)
  }, [])

  async function initializeKinds() {
    try {
      const res = await fetch(apiUrl('/api/kinds'))
      const existingKinds: Kind[] = await res.json()

      // Create default kinds if they don't exist
      for (const defaultKind of DEFAULT_KINDS) {
        const exists = existingKinds.some(k => k.name === defaultKind.name)
        if (!exists) {
          const createRes = await fetch(apiUrl('/api/kinds'), {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              name: defaultKind.name,
              icon: defaultKind.icon,
              template: defaultKind.template,
              attributes: defaultKind.attributes,
            }),
          })
          if (createRes.ok) {
            const newKind = await createRes.json()
            existingKinds.push(newKind)
          } else {
            const error = await createRes.text()
            console.error(`Failed to create default kind ${defaultKind.name}:`, createRes.status, error)
          }
        }
      }

      setKinds(existingKinds)
    } catch (err) {
      console.error('Failed to initialize kinds:', err)
    }
  }

  async function fetchThings() {
    try {
      const url = filterKind ? `/api/things?type=${filterKind}` : '/api/things'
      const res = await fetch(url)
      const data = await res.json()
      setThings(data)
    } catch (err) {
      console.error('Failed to fetch things:', err)
    } finally {
      setLoading(false)
    }
  }

  async function searchThings(query: string) {
    try {
      const res = await fetch(apiUrl(`/api/things/search?q=${encodeURIComponent(query)}`))
      const data = await res.json()
      if (filterKind) {
        setThings(data.filter((t: Thing) => t.type === filterKind))
      } else {
        setThings(data)
      }
    } catch (err) {
      console.error('Failed to search things:', err)
    }
  }

  async function createThing(e: Event) {
    e.preventDefault()
    if (!newContent.trim()) return

    try {
      const res = await fetch(apiUrl('/api/things'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: newType,
          content: newContent,
          metadata: newMetadata,
          visibility: newVisibility,
        }),
      })
      const thing = await res.json()
      setThings([thing, ...things])
      setNewContent('')
      setNewMetadata({})
      setNewVisibility('private')
    } catch (err) {
      console.error('Failed to create thing:', err)
    }
  }

  async function updateThing(thing: Thing) {
    try {
      const res = await fetch(apiUrl(`/api/things/${thing.id}`), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(thing),
      })
      const updated = await res.json()
      setThings(things.map(t => t.id === updated.id ? updated : t))
      setEditingThing(null)
    } catch (err) {
      console.error('Failed to update thing:', err)
    }
  }

  async function deleteThing(id: string) {
    try {
      await fetch(apiUrl(`/api/things/${id}`), { method: 'DELETE' })
      setThings(things.filter(t => t.id !== id))
    } catch (err) {
      console.error('Failed to delete thing:', err)
    }
  }

  // Photo upload state
  const [selectedPhotos, setSelectedPhotos] = useState<Array<{ file: File, caption: string, preview: string }>>([])
  const [showPhotoModal, setShowPhotoModal] = useState(false)
  const [photoContent, setPhotoContent] = useState('')
  const [photoVisibility, setPhotoVisibility] = useState<'private' | 'friends' | 'public'>('private')
  const [dragOverModal, setDragOverModal] = useState(false)

  async function handlePhotoSelect(files: FileList) {
    const newPhotos: Array<{ file: File, caption: string, preview: string }> = []

    for (let i = 0; i < files.length; i++) {
      const file = files[i]
      if (file.type.startsWith('image/') || file.type.startsWith('video/')) {
        // Create preview URL
        const preview = URL.createObjectURL(file)
        newPhotos.push({ file, caption: '', preview })
      }
    }

    setSelectedPhotos(prev => [...prev, ...newPhotos])
    setShowPhotoModal(true)
  }

  async function handlePhotoInputChange(e: Event) {
    const input = e.target as HTMLInputElement
    if (input.files) {
      handlePhotoSelect(input.files)
      input.value = '' // Reset input for re-selection
    }
  }

  // Handle paste events for images
  function handlePaste(e: ClipboardEvent) {
    const items = e.clipboardData?.items
    if (!items) return

    const files = new DataTransfer()
    let hasImages = false

    // First, look for file items (real files or image data)
    for (let i = 0; i < items.length; i++) {
      const item = items[i]

      // Handle file items (images from clipboard, screenshots, etc.)
      if (item.kind === 'file' && (item.type.startsWith('image/') || item.type.startsWith('video/'))) {
        const file = item.getAsFile()
        if (file) {
          files.items.add(file)
          hasImages = true
        }
      }
    }

    // Process pasted files if any were found
    if (hasImages) {
      e.preventDefault()
      handlePhotoSelect(files.files)
      // Focus the modal if not already open
      if (!showPhotoModal) {
        setShowPhotoModal(true)
      }
    }
  }

  async function submitPhotoUpload() {
    if (selectedPhotos.length === 0) return

    setUploading(true)
    try {
      const formData = new FormData()

      // Add all files and captions
      selectedPhotos.forEach((photo) => {
        formData.append('files', photo.file)
        formData.append('captions', photo.caption)
      })

      // Add post content and visibility
      formData.append('content', photoContent)
      formData.append('visibility', photoVisibility)

      const res = await fetch(apiUrl('/api/upload'), {
        method: 'POST',
        body: formData,
        credentials: 'include',
      })

      if (res.ok) {
        const thing = await res.json()
        setThings(prev => [thing, ...prev])

        // Reset state
        setSelectedPhotos([])
        setPhotoContent('')
        setPhotoVisibility('private')
        setShowPhotoModal(false)
      } else {
        const error = await res.json().catch(() => ({ error: res.statusText }))
        console.error('Upload failed:', res.status, error)
        alert(`Upload failed: ${error.error || res.statusText}`)
      }
    } catch (err) {
      console.error('Failed to upload photos:', err)
    } finally {
      setUploading(false)
    }
  }

  function removePhoto(index: number) {
    URL.revokeObjectURL(selectedPhotos[index].preview)
    setSelectedPhotos(prev => prev.filter((_, i) => i !== index))
  }

  function updatePhotoCaption(index: number, caption: string) {
    setSelectedPhotos(prev => {
      const updated = [...prev]
      updated[index].caption = caption
      return updated
    })
  }

  function handleDragOverModal(e: DragEvent) {
    e.preventDefault()
    e.stopPropagation()
    setDragOverModal(true)
  }

  function handleDragLeaveModal(e: DragEvent) {
    e.preventDefault()
    e.stopPropagation()
    setDragOverModal(false)
  }

  function handleDropOnModal(e: DragEvent) {
    e.preventDefault()
    e.stopPropagation()
    setDragOverModal(false)

    const files = e.dataTransfer?.files
    if (files && files.length > 0) {
      handlePhotoSelect(files)
    }
  }

  async function createKind(kind: Partial<Kind>) {
    try {
      const res = await fetch(apiUrl('/api/kinds'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(kind),
      })
      const newKind = await res.json()
      setKinds([...kinds, newKind])
      return newKind
    } catch (err) {
      console.error('Failed to create kind:', err)
    }
  }

  async function updateKind(kind: Kind) {
    try {
      const res = await fetch(apiUrl(`/api/kinds/${kind.id}`), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(kind),
      })
      const updated = await res.json()
      setKinds(prev => prev.map(k => k.id === updated.id ? updated : k))
      setEditingKind(null)
    } catch (err) {
      console.error('Failed to update kind:', err)
    }
  }

  async function deleteKind(id: string) {
    try {
      await fetch(apiUrl(`/api/kinds/${id}`), { method: 'DELETE' })
      setKinds(kinds.filter(k => k.id !== id))
    } catch (err) {
      console.error('Failed to delete kind:', err)
    }
  }

  function getKind(typeName: string): Kind | undefined {
    return kinds.find(k => k.name === typeName)
  }

  function getUsedEmojis(): string[] {
    return kinds.map(k => k.icon).filter(Boolean)
  }

  const currentKind = getKind(newType)

  // Public pages - accessible without authentication
  // All documentation routes now use unified docs page with sidebar
  if (route === '/about' || route.startsWith('/docs') || route === '/guides') {
    return <UnifiedDocsPage />
  }

  // Post detail page - requires authentication
  const postMatch = route.match(/^\/post\/(.+)$/)
  if (postMatch && isAuthenticated) {
    const postId = postMatch[1]
    return (
      <PostPage
        postId={postId}
        kinds={kinds}
        theme={theme}
        isDark={isDark}
        toggleTheme={toggleTheme}
        onLogout={handleLogout}
        onBack={() => navigateTo('/')}
        onDelete={deleteThing}
        isMobile={isMobile}
      />
    )
  }

  // Show nothing while checking auth
  if (isAuthenticated === null) {
    return null
  }

  // Check if we're on the login page (pathname ends with /login)
  const isLoginPage = window.location.pathname.endsWith('/login')

  // Show auth screen if not authenticated
  if (!isAuthenticated) {
    // If explicitly on /login path, show the login form
    if (isLoginPage) {
      return <AuthScreen onAuth={() => setIsAuthenticated(true)} authStatus={authStatus} />
    }
    // Otherwise show the public home page
    return <PublicHomePage theme={theme} onLogin={() => navigateTo('/login')} />
  }

  const sidebarWidth = isMobile ? 60 : 200

  // Navigation items for sidebar
  const navItems = [
    { href: '/', icon: '👤', label: 'Profile', active: isProfilePage },
    { href: '/feed', icon: '📰', label: 'Feed', active: isFeedPage },
    { href: '/bookmarks', icon: '🔖', label: 'Bookmarks', active: isBookmarksPage },
    { href: '/settings', icon: '⚙️', label: 'Settings', active: isSettingsPage },
  ]

  return (
    <div style={{ display: 'flex', minHeight: '100vh', fontFamily: 'system-ui, sans-serif', background: theme.bg, color: theme.text }}>
      {/* Side Menu */}
      <div style={{
        width: sidebarWidth,
        flexShrink: 0,
        background: theme.bgCard,
        borderRight: `1px solid ${theme.border}`,
        display: 'flex',
        flexDirection: 'column',
        position: 'fixed',
        top: 0,
        left: isMobile ? 0 : `calc(50% - ${350 + sidebarWidth}px)`,
        bottom: 0,
        zIndex: 100,
      }}>
        {/* Logo */}
        <a
          href={routeHref('/')}
          style={{
            padding: isMobile ? '16px 0' : '20px 16px',
            textDecoration: 'none',
            color: theme.text,
            display: 'flex',
            alignItems: 'center',
            justifyContent: isMobile ? 'center' : 'flex-start',
            borderBottom: `1px solid ${theme.border}`,
          }}
        >
          <span style={{ fontSize: isMobile ? 20 : 22, fontWeight: 700 }}>
            {isMobile ? 't' : 'tenant'}
          </span>
        </a>

        {/* Navigation */}
        <nav style={{ flex: 1, padding: '12px 0', display: 'flex', flexDirection: 'column', gap: 4 }}>
          {navItems.map(item => (
            <a
              key={item.href}
              href={routeHref(item.href)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 12,
                padding: isMobile ? '12px 0' : '10px 16px',
                justifyContent: isMobile ? 'center' : 'flex-start',
                background: item.active ? theme.accent : 'transparent',
                color: item.active ? theme.accentText : theme.text,
                textDecoration: 'none',
                borderRadius: isMobile ? 0 : 6,
                margin: isMobile ? 0 : '0 8px',
                fontSize: 14,
                fontWeight: item.active ? 600 : 400,
                transition: 'background 0.15s',
              }}
              onMouseEnter={e => !item.active && (e.currentTarget.style.background = theme.bgHover)}
              onMouseLeave={e => !item.active && (e.currentTarget.style.background = 'transparent')}
            >
              <span style={{ fontSize: 18 }}>{item.icon}</span>
              {!isMobile && <span>{item.label}</span>}
            </a>
          ))}
        </nav>

        {/* Bottom actions */}
        <div style={{ padding: isMobile ? '12px 0' : '12px 8px', borderTop: `1px solid ${theme.border}`, display: 'flex', flexDirection: 'column', gap: 4 }}>
          <button
            onClick={toggleTheme}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              padding: isMobile ? '12px 0' : '10px 16px',
              justifyContent: isMobile ? 'center' : 'flex-start',
              background: 'transparent',
              color: theme.textMuted,
              border: 'none',
              borderRadius: isMobile ? 0 : 6,
              margin: isMobile ? 0 : '0 0',
              fontSize: 14,
              cursor: 'pointer',
              width: '100%',
            }}
            title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            <span style={{ fontSize: 18 }}>{isDark ? '☀️' : '🌙'}</span>
            {!isMobile && <span>{isDark ? 'Light' : 'Dark'}</span>}
          </button>
          <button
            onClick={handleLogout}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 12,
              padding: isMobile ? '12px 0' : '10px 16px',
              justifyContent: isMobile ? 'center' : 'flex-start',
              background: 'transparent',
              color: theme.textMuted,
              border: 'none',
              borderRadius: isMobile ? 0 : 6,
              margin: isMobile ? 0 : '0 0',
              fontSize: 14,
              cursor: 'pointer',
              width: '100%',
            }}
          >
            <span style={{ fontSize: 18 }}>🚪</span>
            {!isMobile && <span>Logout</span>}
          </button>
        </div>

        {/* Footer Links */}
        {!isMobile && (
          <div style={{ padding: '12px 16px', borderTop: `1px solid ${theme.border}`, fontSize: 11, color: theme.textSubtle }}>
            <div style={{ marginBottom: 8, color: theme.textMuted }}>
              Your personal social data platform
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 8 }}>
              <a href={routeHref('/docs')} style={{ color: theme.textMuted, textDecoration: 'none' }}>About</a>
              <a href={routeHref('/docs/api')} style={{ color: theme.textMuted, textDecoration: 'none' }}>API</a>
              <a href={routeHref('/docs/deployment')} style={{ color: theme.textMuted, textDecoration: 'none' }}>Deploy</a>
              <a href="https://github.com/russellromney/tenant.social" target="_blank" rel="noopener noreferrer" style={{ color: theme.textMuted, textDecoration: 'none' }}>GitHub</a>
            </div>
            <div>Made with ❤️ in NYC by <a href="https://russellromney.com" target="_blank" rel="noopener noreferrer" style={{ color: theme.link, textDecoration: 'none' }}>me</a></div>
          </div>
        )}
      </div>

      {/* Main Content */}
      <div style={{
        marginLeft: isMobile ? sidebarWidth : `calc(50% - ${350}px)`,
        flex: 1,
        display: 'flex',
        justifyContent: isMobile ? 'center' : 'flex-start',
      }}>
      <div style={{
        width: '100%',
        maxWidth: 700,
        padding: isMobile ? 12 : 20,
      }}>
        {/* Back button for sub-pages */}
        {isSubPage && (
          <div style={{ marginBottom: 16 }}>
            <a
              href={routeHref('/')}
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: 6,
                padding: '8px 16px',
                background: theme.bgHover,
                color: theme.text,
                border: 'none',
                borderRadius: 6,
                fontSize: 14,
                cursor: 'pointer',
                textDecoration: 'none',
              }}
            >
              ← Back
            </a>
          </div>
        )}

      {isSettingsPage ? (
        <SettingsPage
          theme={theme}
          kinds={kinds}
          onImportComplete={() => {
            initializeKinds()
            fetchThings()
          }}
          onCreateKind={createKind}
          onDeleteKind={deleteKind}
          setEditingKind={setEditingKind}
          usedEmojis={getUsedEmojis()}
          isMobile={isMobile}
          defaultKindId={defaultKindId}
          onSetDefaultKind={handleSetDefaultKind}
          initialTab={route === '/friends' ? 'friends' : route === '/kinds' ? 'kinds' : route === '/keys' ? 'keys' : route === '/data' ? 'data' : route === '/integrations' ? 'integrations' : 'kinds'}
        />
      ) : isFeedPage ? (
        <FeedView theme={theme} kinds={kinds} />
      ) : isBookmarksPage ? (
        <BookmarksView theme={theme} kinds={kinds} />
      ) : (
        <>
          {/* Search & Filter */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 16, flexDirection: isMobile ? 'column' : 'row' }}>
            <input
              type="text"
              value={searchQuery}
              onInput={e => setSearchQuery((e.target as HTMLInputElement).value)}
              placeholder="Search things..."
              style={{
                flex: 1,
                padding: isMobile ? '8px 12px' : '10px 14px',
                border: `1px solid ${theme.borderInput}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
              }}
            />
            <select
              value={filterKind}
              onChange={e => setFilterKind((e.target as HTMLSelectElement).value)}
              style={{
                padding: isMobile ? '8px 12px' : '10px 14px',
                border: `1px solid ${theme.borderInput}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
                width: isMobile ? '100%' : 'auto',
              }}
            >
              <option value="">All Kinds</option>
              {kinds.map(kind => (
                <option key={kind.id} value={kind.name}>{kind.icon} {kind.name}</option>
              ))}
            </select>
          </div>

          {/* Compose */}
          <form onSubmit={createThing} style={{ marginBottom: 32 }}>
            <div
              style={{
                background: theme.bgCard,
                border: `2px solid ${theme.borderStrong}`,
                borderRadius: 16,
                overflow: 'hidden',
                transition: 'border-color 0.15s',
              }}
            >
              {/* Top toolbar - Kind selector */}
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '10px 12px',
                  borderBottom: `1px solid ${theme.bgMuted}`,
                }}
              >
                <KindSelector
                  kinds={getSortedKindsByFrequency()}
                  selectedType={newType}
                  onSelectType={setNewType}
                  visibleCount={isMobile ? 2 : 4}
                  theme={theme}
                />
              </div>

              {/* Main input area */}
              <div style={{ padding: '12px 16px' }}>
                <input
                  type="text"
                  value={newContent}
                  onInput={e => setNewContent((e.target as HTMLInputElement).value)}
                  placeholder="What's on your mind?"
                  style={{
                    width: '100%',
                    padding: 0,
                    border: 'none',
                    fontSize: 17,
                    lineHeight: 1.5,
                    outline: 'none',
                    background: 'transparent',
                    boxSizing: 'border-box',
                    fontFamily: 'inherit',
                    color: theme.text,
                  }}
                />

                {/* Kind-specific attributes */}
                {currentKind?.attributes && currentKind.attributes.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 12, paddingTop: 12, borderTop: `1px solid ${theme.bgMuted}` }}>
                    {currentKind.attributes.map(attr => (
                      <AttributeInput
                        key={attr.name}
                        attribute={attr}
                        value={newMetadata[attr.name]}
                        onChange={val => setNewMetadata({ ...newMetadata, [attr.name]: val })}
                        theme={theme}
                      />
                    ))}
                  </div>
                )}
              </div>

              {/* Bottom toolbar - Photo button, Visibility selector, and Post button */}
              <div
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '10px 12px',
                  background: theme.bgToolbar,
                  borderTop: `1px solid ${theme.bgMuted}`,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <button
                    type="button"
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: 4,
                      padding: '6px 12px',
                      background: 'transparent',
                      border: 'none',
                      borderRadius: 6,
                      fontSize: 14,
                      cursor: uploading ? 'wait' : 'pointer',
                      color: theme.textMuted,
                    }}
                    onClick={() => setShowPhotoModal(true)}
                    disabled={uploading}
                  >
                    <span style={{ fontSize: 18 }}>📷</span>
                    <span>{uploading ? 'Uploading...' : 'Photo'}</span>
                    {selectedPhotos.length > 0 && (
                      <span style={{
                        background: theme.accent,
                        color: theme.accentText,
                        borderRadius: '50%',
                        width: 20,
                        height: 20,
                        display: 'flex',
                        alignItems: 'center',
                        justifyContent: 'center',
                        fontSize: 12,
                        fontWeight: 600,
                        marginLeft: 4,
                      }}>
                        {selectedPhotos.length}
                      </span>
                    )}
                  </button>
                  <select
                    value={newVisibility}
                    onChange={e => setNewVisibility((e.target as HTMLSelectElement).value as 'private' | 'friends' | 'public')}
                    style={{
                      padding: '6px 10px',
                      background: theme.bgMuted,
                      border: `1px solid ${theme.border}`,
                      borderRadius: 6,
                      fontSize: 13,
                      color: theme.text,
                      cursor: 'pointer',
                      fontFamily: 'inherit',
                    }}
                  >
                    <option value="private">🔒 Private</option>
                    <option value="friends">👥 Friends</option>
                    <option value="public">🌐 Public</option>
                  </select>
                </div>
                <button
                  type="submit"
                  disabled={!newContent.trim()}
                  style={{
                    padding: '8px 20px',
                    background: newContent.trim() ? theme.accent : theme.textDisabled,
                    color: newContent.trim() ? theme.accentText : theme.textSubtle,
                    border: 'none',
                    borderRadius: 20,
                    fontSize: 14,
                    fontWeight: 600,
                    cursor: newContent.trim() ? 'pointer' : 'not-allowed',
                    transition: 'background 0.15s',
                  }}
                >
                  Post
                </button>
              </div>
            </div>
          </form>

          {/* Feed */}
          {loading ? null : things.length === 0 ? (
            <p style={{ color: theme.textMuted }}>
              {searchQuery || filterKind ? 'No matching things found.' : 'No things yet. Add your first one!'}
            </p>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              {things.map(thing => (
                <ThingCard
                  key={thing.id}
                  thing={thing}
                  kind={getKind(thing.type)}
                  onEdit={() => setEditingThing(thing)}
                  onDelete={() => deleteThing(thing.id)}
                  onUpdateThing={updateThing}
                  theme={theme}
                />
              ))}
            </div>
          )}
        </>
      )}
      </div>
      </div>

      {/* Edit Thing Modal */}
      {editingThing && (
        <EditThingModal
          thing={editingThing}
          kinds={kinds}
          onSave={updateThing}
          onClose={() => setEditingThing(null)}
          theme={theme}
        />
      )}

      {/* Edit Kind Modal */}
      {editingKind && (
        <EditKindModal
          kind={editingKind}
          onSave={updateKind}
          onClose={() => setEditingKind(null)}
          usedEmojis={getUsedEmojis().filter(e => e !== editingKind.icon)}
          theme={theme}
        />
      )}

      {/* Photo Upload Modal */}
      {showPhotoModal && (
        <div
          style={{
            position: 'fixed',
            top: 0,
            left: 0,
            right: 0,
            bottom: 0,
            background: 'rgba(0, 0, 0, 0.5)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: 16,
          }}
          onClick={() => {
            if (!uploading) {
              setShowPhotoModal(false)
              // Keep photos as draft - don't clear!
            }
          }}
        >
          <div
            style={{
              background: dragOverModal ? theme.bgHover : theme.bg,
              borderRadius: 12,
              padding: 24,
              maxWidth: 600,
              maxHeight: '90vh',
              overflow: 'auto',
              width: '100%',
              border: dragOverModal ? `2px dashed ${theme.accent}` : 'none',
              transition: 'all 0.2s',
            }}
            onClick={e => e.stopPropagation()}
            onDragOver={handleDragOverModal as any}
            onDragLeave={handleDragLeaveModal as any}
            onDrop={handleDropOnModal as any}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
              <h2 style={{ margin: 0, color: theme.text, fontSize: 20, fontWeight: 600 }}>
                📷 Upload Photos
              </h2>
              <div style={{ display: 'flex', gap: 8 }}>
                {selectedPhotos.length > 0 && (
                  <button
                    onClick={() => {
                      selectedPhotos.forEach(p => URL.revokeObjectURL(p.preview))
                      setSelectedPhotos([])
                    }}
                    disabled={uploading}
                    style={{
                      background: 'none',
                      border: 'none',
                      fontSize: 13,
                      color: theme.error,
                      cursor: uploading ? 'not-allowed' : 'pointer',
                      opacity: uploading ? 0.5 : 1,
                      fontWeight: 500,
                      padding: 0,
                    }}
                  >
                    Clear All
                  </button>
                )}
                <button
                  onClick={() => {
                    setShowPhotoModal(false)
                    // Don't clear photos - keep as draft!
                  }}
                  disabled={uploading}
                  style={{
                    background: 'none',
                    border: 'none',
                    fontSize: 24,
                    cursor: uploading ? 'not-allowed' : 'pointer',
                    opacity: uploading ? 0.5 : 1,
                  }}
                >
                  ✕
                </button>
              </div>
            </div>

            {/* Photo previews and captions */}
            <div style={{ marginBottom: 20 }}>
              {selectedPhotos.length > 0 ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
                  {selectedPhotos.map((photo, index) => (
                    <div
                      key={index}
                      style={{
                        background: theme.bgMuted,
                        borderRadius: 8,
                        padding: 12,
                        display: 'flex',
                        gap: 12,
                        alignItems: 'flex-start',
                      }}
                    >
                      <img
                        src={photo.preview}
                        alt={`Photo ${index + 1}`}
                        style={{
                          width: 80,
                          height: 80,
                          objectFit: 'cover',
                          borderRadius: 6,
                          flexShrink: 0,
                        }}
                      />
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <label style={{ display: 'block', marginBottom: 6, fontSize: 12, color: theme.textMuted }}>
                          Caption (optional)
                        </label>
                        <input
                          type="text"
                          value={photo.caption}
                          onChange={e => updatePhotoCaption(index, e.currentTarget.value)}
                          placeholder="Add a caption..."
                          disabled={uploading}
                          style={{
                            width: '100%',
                            padding: '8px 10px',
                            border: `1px solid ${theme.borderInput}`,
                            borderRadius: 6,
                            fontSize: 13,
                            background: theme.bgInput,
                            color: theme.text,
                            opacity: uploading ? 0.5 : 1,
                            cursor: uploading ? 'not-allowed' : 'text',
                          }}
                        />
                      </div>
                      <button
                        type="button"
                        onClick={() => removePhoto(index)}
                        disabled={uploading}
                        style={{
                          background: 'none',
                          border: 'none',
                          fontSize: 18,
                          cursor: uploading ? 'not-allowed' : 'pointer',
                          opacity: uploading ? 0.5 : 1,
                          color: theme.error,
                        }}
                      >
                        🗑️
                      </button>
                    </div>
                  ))}
                </div>
              ) : (
                <div style={{
                  textAlign: 'center',
                  padding: 40,
                  color: theme.textMuted,
                }}>
                  <p style={{ margin: '0 0 8px 0', fontSize: 14 }}>📁 Drag and drop photos here</p>
                  <p style={{ margin: '0 0 12px 0', fontSize: 13, color: theme.textSubtle }}>or use the Photo button to select files</p>
                  <input
                    type="file"
                    accept="image/*,video/*"
                    multiple
                    onChange={handlePhotoInputChange}
                    style={{ display: 'none' }}
                    disabled={uploading}
                    id="photo-modal-input"
                  />
                  <button
                    type="button"
                    style={{
                      display: 'inline-block',
                      padding: '8px 16px',
                      background: theme.accent,
                      color: theme.accentText,
                      borderRadius: 6,
                      fontSize: 13,
                      fontWeight: 500,
                      cursor: uploading ? 'not-allowed' : 'pointer',
                      border: 'none',
                      opacity: uploading ? 0.5 : 1,
                    }}
                    onClick={() => {
                      const input = document.getElementById('photo-modal-input') as HTMLInputElement
                      input?.click()
                    }}
                    disabled={uploading}
                  >
                    Choose Photos
                  </button>
                </div>
              )}
            </div>

            {/* Post content and visibility */}
            <div style={{ marginBottom: 20, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <label style={{ display: 'block', marginBottom: 6, fontSize: 12, color: theme.textMuted, fontWeight: 500 }}>
                  Post content (optional)
                </label>
                <textarea
                  value={photoContent}
                  onChange={e => setPhotoContent(e.currentTarget.value)}
                  placeholder="Add a caption for your gallery..."
                  disabled={uploading}
                  style={{
                    width: '100%',
                    padding: '10px 12px',
                    border: `1px solid ${theme.borderInput}`,
                    borderRadius: 6,
                    fontSize: 13,
                    background: theme.bgInput,
                    color: theme.text,
                    fontFamily: 'inherit',
                    minHeight: 60,
                    resize: 'vertical',
                    opacity: uploading ? 0.5 : 1,
                    cursor: uploading ? 'not-allowed' : 'text',
                  }}
                />
              </div>

              <div>
                <label style={{ display: 'block', marginBottom: 6, fontSize: 12, color: theme.textMuted, fontWeight: 500 }}>
                  Visibility
                </label>
                <select
                  value={photoVisibility}
                  onChange={e => setPhotoVisibility(e.currentTarget.value as 'private' | 'friends' | 'public')}
                  disabled={uploading}
                  style={{
                    width: '100%',
                    padding: '8px 10px',
                    border: `1px solid ${theme.borderInput}`,
                    borderRadius: 6,
                    fontSize: 13,
                    background: theme.bgInput,
                    color: theme.text,
                    opacity: uploading ? 0.5 : 1,
                    cursor: uploading ? 'not-allowed' : 'pointer',
                  }}
                >
                  <option value="private">🔒 Private (only me)</option>
                  <option value="friends">👥 Friends (me + connections)</option>
                  <option value="public">🌐 Public (everyone)</option>
                </select>
              </div>
            </div>

            {/* Action buttons */}
            <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
              <button
                onClick={() => {
                  setShowPhotoModal(false)
                  // Keep photos as draft - don't clear!
                }}
                disabled={uploading}
                style={{
                  padding: '8px 16px',
                  background: theme.bgMuted,
                  border: 'none',
                  borderRadius: 6,
                  fontSize: 13,
                  fontWeight: 500,
                  cursor: uploading ? 'not-allowed' : 'pointer',
                  color: theme.text,
                  opacity: uploading ? 0.5 : 1,
                }}
              >
                Close
              </button>
              <button
                type="button"
                onClick={submitPhotoUpload}
                disabled={uploading || selectedPhotos.length === 0}
                style={{
                  padding: '8px 16px',
                  background: uploading || selectedPhotos.length === 0 ? theme.textDisabled : theme.accent,
                  border: 'none',
                  borderRadius: 6,
                  fontSize: 13,
                  fontWeight: 600,
                  cursor: uploading || selectedPhotos.length === 0 ? 'not-allowed' : 'pointer',
                  color: uploading || selectedPhotos.length === 0 ? theme.textSubtle : theme.accentText,
                }}
              >
                {uploading ? 'Uploading...' : `Upload ${selectedPhotos.length} Photo${selectedPhotos.length !== 1 ? 's' : ''}`}
              </button>
            </div>
          </div>
        </div>
      )}

    </div>
  )
}

// Responsive Kind Selector Component
function KindSelector({
  kinds,
  selectedType,
  onSelectType,
  visibleCount,
  theme,
}: {
  kinds: Kind[]
  selectedType: string
  onSelectType: (type: string) => void
  visibleCount: number
  theme: Theme
}) {
  const visibleKinds = kinds.slice(0, visibleCount)
  const hiddenKinds = kinds.slice(visibleCount)
  const selectedKind = kinds.find(k => k.name === selectedType)
  const selectedInHidden = hiddenKinds.some(k => k.name === selectedType)

  return (
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
      {/* Visible kinds */}
      {visibleKinds.map(kind => {
        const isSelected = kind.name === selectedType
        return (
          <button
            key={kind.id}
            type="button"
            onClick={() => onSelectType(kind.name)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              padding: '5px 10px',
              fontSize: 13,
              border: 'none',
              borderRadius: 4,
              cursor: 'pointer',
              background: isSelected ? theme.accent : theme.bgMuted,
              color: isSelected ? theme.accentText : theme.textSecondary,
              fontWeight: 500,
              transition: 'all 0.15s',
            }}
          >
            <span>{kind.icon}</span>
            <span>{kind.name}</span>
          </button>
        )
      })}

      {/* Native select dropdown for hidden kinds */}
      {hiddenKinds.length > 0 && (
        <select
          value={selectedInHidden ? selectedType : ''}
          onChange={e => {
            if (e.currentTarget.value) {
              onSelectType(e.currentTarget.value)
            }
          }}
          style={{
            padding: '5px 8px',
            fontSize: 13,
            border: 'none',
            borderRadius: 4,
            cursor: 'pointer',
            background: selectedInHidden ? theme.accent : theme.bgMuted,
            color: selectedInHidden ? theme.accentText : theme.textMuted,
            fontWeight: 500,
          }}
        >
          <option value="" disabled={selectedInHidden}>
            {selectedInHidden && selectedKind ? `${selectedKind.icon} ${selectedKind.name}` : 'More...'}
          </option>
          {hiddenKinds.map(kind => (
            <option key={kind.id} value={kind.name}>
              {kind.icon} {kind.name}
            </option>
          ))}
        </select>
      )}
    </div>
  )
}

// ==================== REACTION & BOOKMARK COMPONENTS ====================

// Format relative time (e.g., "2h ago", "3d ago")
function formatRelativeTime(dateString: string): string {
  const date = new Date(dateString)
  const now = new Date()
  const diffMs = now.getTime() - date.getTime()
  const diffMins = Math.floor(diffMs / 60000)
  const diffHours = Math.floor(diffMs / 3600000)
  const diffDays = Math.floor(diffMs / 86400000)

  if (diffMins < 1) return 'just now'
  if (diffMins < 60) return `${diffMins}m ago`
  if (diffHours < 24) return `${diffHours}h ago`
  if (diffDays < 7) return `${diffDays}d ago`
  return date.toLocaleDateString()
}

// Common emoji reactions for quick picker
const QUICK_EMOJIS = ['❤️', '👍', '😂', '😮', '😢', '🔥', '👏', '🎉']

// ReactionBar - shows and manages reactions for a thing or comment
function ReactionBar({
  targetId,
  targetType,
  reactions,
  onReactionsChange,
  theme,
  compact = false,
}: {
  targetId: string
  targetType: 'thing' | 'comment'
  reactions: ReactionSummary | null
  onReactionsChange: (reactions: ReactionSummary) => void
  theme: Theme
  compact?: boolean
}) {
  const [loading, setLoading] = useState(false)
  const [showEmojiPicker, setShowEmojiPicker] = useState(false)

  const likeCount = reactions?.counts?.['like'] || 0
  const hasLiked = reactions?.user_reactions?.includes('like') || false

  // Get emoji reactions (excluding 'like')
  const emojiReactions = Object.entries(reactions?.counts || {})
    .filter(([key]) => key !== 'like')
    .sort((a, b) => b[1] - a[1])

  const endpoint = targetType === 'thing'
    ? `/api/things/${targetId}/reactions`
    : `/api/comments/${targetId}/reactions`

  const toggleLike = async () => {
    if (loading) return
    setLoading(true)
    try {
      if (hasLiked) {
        const resp = await fetch(apiUrl(`${endpoint}/like`), { method: 'DELETE', credentials: 'include' })
        if (resp.ok) {
          const data = await resp.json()
          onReactionsChange(data.data)
        }
      } else {
        const resp = await fetch(apiUrl(endpoint), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ reaction_type: 'like' }),
        })
        if (resp.ok) {
          const data = await resp.json()
          onReactionsChange(data.data)
        }
      }
    } finally {
      setLoading(false)
    }
  }

  const addEmojiReaction = async (emoji: string) => {
    if (loading) return
    setLoading(true)
    setShowEmojiPicker(false)
    try {
      // Check if user already has this emoji
      const hasEmoji = reactions?.user_reactions?.includes(emoji)
      if (hasEmoji) {
        // Remove it
        const resp = await fetch(apiUrl(`${endpoint}/${encodeURIComponent(emoji)}`), {
          method: 'DELETE',
          credentials: 'include',
        })
        if (resp.ok) {
          const data = await resp.json()
          onReactionsChange(data.data)
        }
      } else {
        // Add it
        const resp = await fetch(apiUrl(endpoint), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ reaction_type: 'emoji', emoji }),
        })
        if (resp.ok) {
          const data = await resp.json()
          onReactionsChange(data.data)
        }
      }
    } finally {
      setLoading(false)
    }
  }

  const buttonStyle = {
    background: 'none',
    border: 'none',
    cursor: loading ? 'wait' : 'pointer',
    padding: compact ? '2px 6px' : '4px 8px',
    borderRadius: 4,
    fontSize: compact ? 13 : 14,
    display: 'flex',
    alignItems: 'center',
    gap: 4,
    color: theme.textMuted,
    transition: 'background 0.15s',
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: compact ? 6 : 10, flexWrap: 'wrap' }}>
      {/* Like button */}
      <button
        onClick={toggleLike}
        style={{
          ...buttonStyle,
          color: hasLiked ? '#e25555' : theme.textMuted,
          background: hasLiked ? 'rgba(226, 85, 85, 0.1)' : 'transparent',
        }}
        onMouseEnter={e => { if (!hasLiked) e.currentTarget.style.background = theme.bgMuted }}
        onMouseLeave={e => { if (!hasLiked) e.currentTarget.style.background = 'transparent' }}
        title={hasLiked ? 'Unlike' : 'Like'}
      >
        <span>{hasLiked ? '❤️' : '🤍'}</span>
        {likeCount > 0 && <span>{likeCount}</span>}
      </button>

      {/* Emoji reactions */}
      {emojiReactions.map(([emoji, count]) => {
        const hasReacted = reactions?.user_reactions?.includes(emoji)
        return (
          <button
            key={emoji}
            onClick={() => addEmojiReaction(emoji)}
            style={{
              ...buttonStyle,
              background: hasReacted ? 'rgba(100, 100, 100, 0.15)' : 'transparent',
            }}
            onMouseEnter={e => e.currentTarget.style.background = theme.bgMuted}
            onMouseLeave={e => e.currentTarget.style.background = hasReacted ? 'rgba(100, 100, 100, 0.15)' : 'transparent'}
          >
            <span>{emoji}</span>
            {count > 0 && <span>{count}</span>}
          </button>
        )
      })}

      {/* Add emoji button */}
      <div style={{ position: 'relative' }}>
        <button
          onClick={() => setShowEmojiPicker(!showEmojiPicker)}
          style={{
            ...buttonStyle,
            fontSize: compact ? 11 : 12,
          }}
          onMouseEnter={e => e.currentTarget.style.background = theme.bgMuted}
          onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          title="Add reaction"
        >
          +
        </button>

        {/* Emoji picker dropdown */}
        {showEmojiPicker && (
          <div
            style={{
              position: 'absolute',
              bottom: '100%',
              left: 0,
              marginBottom: 4,
              background: theme.bgCard,
              border: `1px solid ${theme.border}`,
              borderRadius: 8,
              padding: 8,
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: 4,
              zIndex: 100,
              boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
            }}
          >
            {QUICK_EMOJIS.map(emoji => (
              <button
                key={emoji}
                onClick={() => addEmojiReaction(emoji)}
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  fontSize: 18,
                  padding: 4,
                  borderRadius: 4,
                }}
                onMouseEnter={e => e.currentTarget.style.background = theme.bgMuted}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                {emoji}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// BookmarkButton - toggle bookmark for a thing
function BookmarkButton({
  thingId,
  isBookmarked,
  onBookmarkChange,
  theme,
}: {
  thingId: string
  isBookmarked: boolean
  onBookmarkChange: (bookmarked: boolean) => void
  theme: Theme
}) {
  const [loading, setLoading] = useState(false)

  const toggleBookmark = async () => {
    if (loading) return
    setLoading(true)
    try {
      if (isBookmarked) {
        const resp = await fetch(apiUrl(`/api/bookmarks/${thingId}`), {
          method: 'DELETE',
          credentials: 'include',
        })
        if (resp.ok) {
          onBookmarkChange(false)
        }
      } else {
        const resp = await fetch(apiUrl('/api/bookmarks'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ thing_id: thingId }),
        })
        if (resp.ok) {
          onBookmarkChange(true)
        }
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <button
      onClick={(e) => {
        e.stopPropagation()
        toggleBookmark()
      }}
      style={{
        background: 'none',
        border: 'none',
        color: isBookmarked ? theme.accent : theme.textDisabled,
        cursor: loading ? 'wait' : 'pointer',
        fontSize: 16,
        padding: '4px 8px',
        flexShrink: 0,
      }}
      onMouseEnter={e => { if (!isBookmarked) e.currentTarget.style.color = theme.accent }}
      onMouseLeave={e => { if (!isBookmarked) e.currentTarget.style.color = theme.textDisabled }}
      title={isBookmarked ? 'Remove bookmark' : 'Bookmark'}
    >
      {isBookmarked ? '🔖' : '🏷️'}
    </button>
  )
}

// EditedIndicator - shows "edited" with click to view history
function EditedIndicator({
  editedAt,
  onClick,
  theme,
}: {
  editedAt: string
  onClick: () => void
  theme: Theme
}) {
  return (
    <button
      onClick={(e) => {
        e.stopPropagation()
        onClick()
      }}
      style={{
        background: 'none',
        border: 'none',
        color: theme.textMuted,
        cursor: 'pointer',
        fontSize: 11,
        padding: '2px 4px',
        textDecoration: 'underline',
        textDecorationStyle: 'dotted',
      }}
      title="View edit history"
    >
      edited {formatRelativeTime(editedAt)}
    </button>
  )
}

// EditHistoryModal - shows all previous versions of content
function EditHistoryModal({
  targetId,
  targetType,
  onClose,
  theme,
}: {
  targetId: string
  targetType: 'thing' | 'comment'
  onClose: () => void
  theme: Theme
}) {
  const [history, setHistory] = useState<EditHistoryEntry[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const endpoint = targetType === 'thing'
          ? `/api/things/${targetId}/history`
          : `/api/comments/${targetId}/history`
        const resp = await fetch(apiUrl(endpoint), { credentials: 'include' })
        if (resp.ok) {
          const data = await resp.json()
          setHistory(data.data || [])
        }
      } finally {
        setLoading(false)
      }
    }
    fetchHistory()
  }, [targetId, targetType])

  // Close on escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'rgba(0, 0, 0, 0.6)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: theme.bgCard,
          borderRadius: 12,
          padding: 24,
          maxWidth: 600,
          width: '90%',
          maxHeight: '80vh',
          overflow: 'auto',
          boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
        }}
        onClick={e => e.stopPropagation()}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ margin: 0, color: theme.text }}>Edit History</h3>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              fontSize: 20,
              cursor: 'pointer',
              color: theme.textMuted,
            }}
          >
            ×
          </button>
        </div>

        {loading ? (
          <div style={{ color: theme.textMuted, textAlign: 'center', padding: 20 }}>Loading...</div>
        ) : history.length === 0 ? (
          <div style={{ color: theme.textMuted, textAlign: 'center', padding: 20 }}>No edit history available</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {history.map((entry, index) => (
              <div
                key={entry.id}
                style={{
                  padding: 12,
                  background: theme.bgMuted,
                  borderRadius: 8,
                  border: `1px solid ${theme.border}`,
                }}
              >
                <div style={{ fontSize: 11, color: theme.textMuted, marginBottom: 8 }}>
                  {index === 0 ? 'Previous version' : `Version ${history.length - index}`} • {formatRelativeTime(entry.edited_at)}
                </div>
                <div style={{ color: theme.text, whiteSpace: 'pre-wrap', fontSize: 14 }}>
                  {entry.content}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ThingCard Component - renders a Thing based on its Kind's template
function ThingCard({
  thing,
  kind,
  onEdit,
  onDelete,
  onUpdateThing,
  theme,
  isDetailView = false,
}: {
  thing: Thing
  kind: Kind | undefined
  isDetailView?: boolean
  onEdit: () => void
  onDelete: () => void
  onUpdateThing: (thing: Thing) => void
  theme: Theme
}) {
  const template = kind?.template || 'default'
  const icon = kind?.icon || '•'

  // Photo template hooks - MUST be at top level, always called regardless of template
  const [currentPhotoIndex, setCurrentPhotoIndex] = useState(0)
  const [viewerOpen, setViewerOpen] = useState(false)
  const [captionExpanded, setCaptionExpanded] = useState(false)

  // Reactions, bookmarks, and edit history state
  const [reactions, setReactions] = useState<ReactionSummary | null>(null)
  const [isBookmarked, setIsBookmarked] = useState(false)
  const [showHistoryModal, setShowHistoryModal] = useState(false)

  // Fetch reactions and bookmark status on mount
  useEffect(() => {
    const fetchReactionsAndBookmark = async () => {
      try {
        // Fetch reactions
        const reactionsResp = await fetch(apiUrl(`/api/things/${thing.id}/reactions`), { credentials: 'include' })
        if (reactionsResp.ok) {
          const data = await reactionsResp.json()
          setReactions(data.data)
        }

        // Fetch bookmark status
        const bookmarkResp = await fetch(apiUrl(`/api/things/${thing.id}/bookmark`), { credentials: 'include' })
        if (bookmarkResp.ok) {
          const data = await bookmarkResp.json()
          setIsBookmarked(data.data?.bookmarked || false)
        }
      } catch (e) {
        console.error('Failed to fetch reactions/bookmark:', e)
      }
    }
    fetchReactionsAndBookmark()
  }, [thing.id])

  // Photo Viewer Modal - keyboard navigation
  useEffect(() => {
    if (!viewerOpen || template !== 'photo' || !thing.photos) return
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setViewerOpen(false)
      } else if (e.key === 'ArrowLeft') {
        setCurrentPhotoIndex((prev) => (prev === 0 ? thing.photos!.length - 1 : prev - 1))
      } else if (e.key === 'ArrowRight') {
        setCurrentPhotoIndex((prev) => (prev === thing.photos!.length - 1 ? 0 : prev + 1))
      }
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [viewerOpen, thing.photos, template])

  // Delete button (shared across templates)
  const DeleteButton = () => (
    <button
      onClick={(e) => {
        e.stopPropagation()
        onDelete()
      }}
      style={{
        background: 'none',
        border: 'none',
        color: theme.textDisabled,
        cursor: 'pointer',
        fontSize: 18,
        padding: '4px 8px',
        flexShrink: 0,
      }}
      onMouseEnter={e => (e.currentTarget.style.color = theme.error)}
      onMouseLeave={e => (e.currentTarget.style.color = theme.textDisabled)}
    >
      ×
    </button>
  )

  // Edit button (shared across templates)
  const EditButton = () => (
    <button
      onClick={(e) => {
        e.stopPropagation()
        onEdit()
      }}
      style={{
        background: 'none',
        border: 'none',
        color: theme.textDisabled,
        cursor: 'pointer',
        fontSize: 14,
        padding: '4px 8px',
        flexShrink: 0,
      }}
      onMouseEnter={e => (e.currentTarget.style.color = theme.accent)}
      onMouseLeave={e => (e.currentTarget.style.color = theme.textDisabled)}
      title="Edit"
    >
      ✎
    </button>
  )

  // Navigate to post detail page
  const handleCardClick = () => {
    if (!isDetailView) {
      // Save scroll position before navigating
      sessionStorage.setItem('feedScrollPosition', String(window.scrollY))
      navigateTo(`/post/${thing.id}`)
    }
  }

  // Attributes display (shared across templates)
  const AttributesDisplay = ({ compact = false }: { compact?: boolean }) => {
    if (!kind?.attributes || Object.keys(thing.metadata || {}).length === 0) return null
    return (
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: compact ? 4 : 8, marginTop: compact ? 4 : 8 }}>
        {kind.attributes.map(attr => {
          const val = thing.metadata?.[attr.name]
          if (val === undefined || val === null || val === '') return null

          // Handle link type attributes - skip them here, they're shown separately
          if (attr.type === 'link') return null

          return (
            <span
              key={attr.name}
              style={{
                fontSize: compact ? 11 : 12,
                padding: compact ? '1px 6px' : '2px 8px',
                background: theme.bgMuted,
                borderRadius: 4,
                color: theme.textMuted,
              }}
            >
              {attr.type === 'checkbox' ? (val ? '✓ ' : '○ ') : ''}
              {attr.type === 'url' ? (
                <a
                  href={String(val)}
                  target="_blank"
                  onClick={e => e.stopPropagation()}
                  style={{ color: theme.link, textDecoration: 'none' }}
                >
                  {attr.name}
                </a>
              ) : (
                <>{attr.name}: {attr.type === 'checkbox' ? (val ? 'Yes' : 'No') : String(val)}</>
              )}
            </span>
          )
        })}
      </div>
    )
  }

  // Display linked Things
  const LinkedThingsDisplay = () => {
    if (!kind?.attributes) return null
    const linkAttrs = kind.attributes.filter(a => a.type === 'link')
    if (linkAttrs.length === 0) return null

    const linkedThingIds = new Set<string>()
    linkAttrs.forEach(attr => {
      const val = thing.metadata?.[attr.name]
      if (Array.isArray(val)) {
        val.forEach((id: string) => linkedThingIds.add(id))
      }
    })

    if (linkedThingIds.size === 0) return null

    return (
      <div style={{ marginTop: 12 }}>
        <div style={{ fontSize: 12, color: theme.textMuted, marginBottom: 6, fontWeight: 500 }}>
          Linked Things
        </div>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
          {Array.from(linkedThingIds).map(linkedId => (
            <div
              key={linkedId}
              onClick={(e) => {
                e.stopPropagation()
                navigateTo(`/post/${linkedId}`)
              }}
              style={{
                padding: '4px 10px',
                background: theme.link,
                color: theme.bgCard,
                borderRadius: 4,
                fontSize: 12,
                cursor: 'pointer',
                transition: 'opacity 0.15s',
              }}
              onMouseEnter={e => (e.currentTarget.style.opacity = '0.8')}
              onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
            >
              {linkedId.slice(0, 8)}...
            </div>
          ))}
        </div>
      </div>
    )
  }

  // COMPACT template - minimal one-line display
  if (template === 'compact') {
    return (
      <div
        onClick={handleCardClick}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '10px 14px',
          background: theme.bgCard,
          borderRadius: 6,
          border: `1px solid ${theme.border}`,
          cursor: 'pointer',
          transition: 'background 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.background = theme.bgHover)}
        onMouseLeave={e => (e.currentTarget.style.background = theme.bgCard)}
      >
        <span style={{ fontSize: 16 }}>{icon}</span>
        <span style={{ flex: 1, fontSize: 14, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: theme.text }}>
          {thing.content}
        </span>
        <span style={{ fontSize: 11, color: theme.textSubtle, flexShrink: 0 }}>
          {new Date(thing.created_at).toLocaleDateString()}
        </span>
        <EditButton />
      </div>
    )
  }

  // CHECKLIST template - task-style with checkbox
  if (template === 'checklist') {
    const isDone = Boolean(thing.metadata?.done)
    return (
      <div
        style={{
          display: 'flex',
          alignItems: 'flex-start',
          gap: 12,
          padding: '12px 14px',
          background: theme.bgCard,
          borderRadius: 8,
          border: `1px solid ${theme.border}`,
          cursor: 'pointer',
          transition: 'background 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.background = theme.bgHover)}
        onMouseLeave={e => (e.currentTarget.style.background = theme.bgCard)}
      >
        <input
          type="checkbox"
          checked={isDone}
          onChange={(e) => {
            e.stopPropagation()
            onUpdateThing({ ...thing, metadata: { ...thing.metadata, done: !isDone } })
          }}
          style={{ width: 18, height: 18, marginTop: 2, cursor: 'pointer', accentColor: theme.accent }}
        />
        <div style={{ flex: 1 }} onClick={handleCardClick}>
          <span
            style={{
              fontSize: 15,
              textDecoration: isDone ? 'line-through' : 'none',
              color: isDone ? theme.textSubtle : theme.text,
            }}
          >
            {thing.content}
          </span>
          <AttributesDisplay compact />
        </div>
        <span style={{ fontSize: 11, color: theme.textSubtle, flexShrink: 0 }}>
          {new Date(thing.created_at).toLocaleDateString()}
        </span>
        <EditButton />
      </div>
    )
  }

  // LINK template - URL-focused
  if (template === 'link') {
    const url = thing.metadata?.url as string | undefined
    return (
      <div
        onClick={handleCardClick}
        style={{
          padding: 14,
          background: theme.bgCard,
          borderRadius: 8,
          border: `1px solid ${theme.border}`,
          borderLeft: `4px solid ${theme.accent}`,
          cursor: 'pointer',
          transition: 'box-shadow 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 2px 8px ${theme.shadow}`)}
        onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span style={{ fontSize: 16 }}>{icon}</span>
              <span style={{ fontSize: 15, fontWeight: 500, color: theme.text }}>{thing.content}</span>
            </div>
            {url && (
              <a
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                onClick={e => e.stopPropagation()}
                style={{
                  fontSize: 13,
                  color: theme.link,
                  textDecoration: 'none',
                  display: 'block',
                  overflow: 'hidden',
                  textOverflow: 'ellipsis',
                  whiteSpace: 'nowrap',
                  maxWidth: '100%',
                }}
              >
                {url}
              </a>
            )}
            <div style={{ fontSize: 11, color: theme.textSubtle, marginTop: 6 }}>
              {new Date(thing.created_at).toLocaleDateString()}
            </div>
          </div>
          <EditButton />
        </div>
      </div>
    )
  }

  // CARD template - rich card with prominent content
  if (template === 'card') {
    return (
      <div
        onClick={handleCardClick}
        style={{
          background: theme.bgCard,
          borderRadius: 12,
          border: `1px solid ${theme.border}`,
          overflow: 'hidden',
          cursor: 'pointer',
          transition: 'box-shadow 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 4px 12px ${theme.shadow}`)}
        onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
      >
        <div style={{ background: theme.bgHover, padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 20 }}>{icon}</span>
          <span style={{ fontSize: 12, fontWeight: 600, color: theme.textMuted, textTransform: 'uppercase', letterSpacing: 0.5 }}>
            {thing.type}
          </span>
          <div style={{ flex: 1 }} />
          <EditButton />
        </div>
        <div style={{ padding: 16 }}>
          <Markdown content={thing.content} theme={theme} className="markdown-content" />
          <AttributesDisplay />
          <p style={{ fontSize: 12, color: theme.textSubtle, margin: '12px 0 0' }}>
            {new Date(thing.created_at).toLocaleString()}
          </p>
        </div>
      </div>
    )
  }

  // PHOTO template - image/video display
  if (template === 'photo') {
    // Handle gallery with multiple photos
    if (thing.photos && thing.photos.length > 0) {
      const currentPhoto = thing.photos[currentPhotoIndex]
      const isVideo = currentPhoto.content_type?.startsWith('video/')

      const PhotoViewer = () => {
        if (!viewerOpen) return null
        return (
          <div
            onClick={() => setViewerOpen(false)}
            style={{
              position: 'fixed',
              top: 0,
              left: 0,
              right: 0,
              bottom: 0,
              background: 'rgba(0, 0, 0, 0.95)',
              zIndex: 10000,
              display: 'flex',
              flexDirection: 'column',
              cursor: 'zoom-out',
            }}
          >
            {/* Close button */}
            <button
              onClick={() => setViewerOpen(false)}
              style={{
                position: 'absolute',
                top: 16,
                right: 16,
                background: 'rgba(255, 255, 255, 0.1)',
                border: 'none',
                color: '#fff',
                fontSize: 24,
                padding: '8px 16px',
                borderRadius: 8,
                cursor: 'pointer',
                zIndex: 10001,
              }}
            >
              ×
            </button>

            {/* Photo area - takes remaining space */}
            <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', position: 'relative', minHeight: 0 }}>
              {/* Navigation arrows */}
              {thing.photos!.length > 1 && (
                <>
                  <button
                    onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === 0 ? thing.photos!.length - 1 : prev - 1)) }}
                    style={{
                      position: 'absolute',
                      left: 16,
                      top: '50%',
                      transform: 'translateY(-50%)',
                      background: 'rgba(255, 255, 255, 0.1)',
                      color: '#fff',
                      border: 'none',
                      padding: '16px 24px',
                      borderRadius: 8,
                      cursor: 'pointer',
                      fontSize: 24,
                      zIndex: 10001,
                    }}
                  >
                    ‹
                  </button>
                  <button
                    onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === thing.photos!.length - 1 ? 0 : prev + 1)) }}
                    style={{
                      position: 'absolute',
                      right: 16,
                      top: '50%',
                      transform: 'translateY(-50%)',
                      background: 'rgba(255, 255, 255, 0.1)',
                      color: '#fff',
                      border: 'none',
                      padding: '16px 24px',
                      borderRadius: 8,
                      cursor: 'pointer',
                      fontSize: 24,
                      zIndex: 10001,
                    }}
                  >
                    ›
                  </button>
                </>
              )}

              {/* Full-size image */}
              <div onClick={(e) => e.stopPropagation()} style={{ maxWidth: '100%', maxHeight: '100%', cursor: 'default', position: 'relative' }}>
                {isVideo ? (
                  <video
                    src={apiUrl(`/api/photos/${currentPhoto.id}?size=full`)}
                    controls
                    autoPlay
                    style={{ maxWidth: '100vw', maxHeight: '60vh', objectFit: 'contain' }}
                  />
                ) : (
                  <img
                    src={apiUrl(`/api/photos/${currentPhoto.id}?size=full`)}
                    alt={currentPhoto.caption || 'Photo'}
                    style={{ maxWidth: '100vw', maxHeight: '60vh', objectFit: 'contain' }}
                  />
                )}
                {thing.photos!.length > 1 && (
                  <p style={{ color: 'rgba(255,255,255,0.6)', textAlign: 'center', marginTop: 8, fontSize: 12 }}>
                    {currentPhotoIndex + 1} / {thing.photos!.length}
                  </p>
                )}
              </div>
            </div>

            {/* Bottom section - caption and comments stub */}
            <div
              onClick={(e) => e.stopPropagation()}
              style={{
                background: theme.bgCard,
                borderTop: `1px solid ${theme.border}`,
                padding: 16,
                cursor: 'default',
                maxHeight: '40vh',
                overflowY: 'auto',
              }}
            >
              {/* Caption */}
              {currentPhoto.caption && (
                <div
                  onClick={(e) => { e.stopPropagation(); setCaptionExpanded(!captionExpanded) }}
                  style={{
                    color: theme.text,
                    fontSize: 14,
                    marginBottom: 12,
                    cursor: 'pointer',
                    ...(captionExpanded ? {} : {
                      maxHeight: '4.5em',
                      overflow: 'hidden',
                      textOverflow: 'ellipsis',
                      display: '-webkit-box',
                      WebkitLineClamp: 3,
                      WebkitBoxOrient: 'vertical',
                    })
                  }}
                >
                  {currentPhoto.caption}
                </div>
              )}

              {/* Post content */}
              {thing.content && (
                <div style={{ color: theme.text, fontSize: 14, marginBottom: 12, paddingBottom: 12, borderBottom: `1px solid ${theme.border}` }}>
                  <Markdown content={thing.content} theme={theme} className="markdown-content" />
                </div>
              )}

              {/* Replies link */}
              <div style={{ color: theme.textMuted, fontSize: 13, paddingTop: 8 }}>
                <a
                  href={`/post/${thing.id}`}
                  onClick={(e) => { e.stopPropagation(); navigateTo(`/post/${thing.id}`) }}
                  style={{ color: theme.accent, textDecoration: 'none' }}
                >
                  View replies →
                </a>
              </div>
            </div>
          </div>
        )
      }

      // Two-column layout for desktop detail view
      // Two-column layout for photo viewer modal
      if (viewerOpen && window.innerWidth > 768) {
        return (
          <>
            {/* Modal backdrop */}
            <div
              onClick={() => setViewerOpen(false)}
              style={{
                position: 'fixed',
                top: 0,
                left: 0,
                right: 0,
                bottom: 0,
                background: 'rgba(0, 0, 0, 0.9)',
                zIndex: 9999,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                padding: 40,
              }}
            >
              <div
                onClick={(e) => e.stopPropagation()}
                style={{
                  display: 'grid',
                  gridTemplateColumns: '1fr 400px',
                  gap: 0,
                  background: theme.bgCard,
                  borderRadius: 12,
                  border: `1px solid ${theme.border}`,
                  overflow: 'hidden',
                  maxWidth: 1400,
                  maxHeight: '90vh',
                  width: '100%',
                }}
              >
              {/* Left column: Photo gallery (sticky) */}
              <div style={{ position: 'relative', background: '#000', display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: 500, maxHeight: '80vh' }}>
                {isVideo ? (
                  <video
                    src={apiUrl(`/api/photos/${currentPhoto.id}?size=full`)}
                    controls
                    style={{
                      maxWidth: '100%',
                      maxHeight: '80vh',
                      width: 'auto',
                      height: 'auto',
                      objectFit: 'contain',
                      display: 'block',
                    }}
                  />
                ) : (
                  <img
                    src={apiUrl(`/api/photos/${currentPhoto.id}?size=full`)}
                    alt={currentPhoto.caption || 'Photo'}
                    style={{
                      maxWidth: '100%',
                      maxHeight: '80vh',
                      width: 'auto',
                      height: 'auto',
                      objectFit: 'contain',
                      display: 'block',
                    }}
                  />
                )}

                {/* Carousel Navigation */}
                {thing.photos!.length > 1 && (
                  <>
                    <button
                      type="button"
                      onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === 0 ? thing.photos!.length - 1 : prev - 1)) }}
                      style={{
                        position: 'absolute',
                        left: 16,
                        top: '50%',
                        transform: 'translateY(-50%)',
                        background: 'rgba(0, 0, 0, 0.5)',
                        color: '#fff',
                        border: 'none',
                        padding: '12px 20px',
                        borderRadius: 8,
                        cursor: 'pointer',
                        fontSize: 24,
                      }}
                    >
                      ‹
                    </button>
                    <button
                      type="button"
                      onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === thing.photos!.length - 1 ? 0 : prev + 1)) }}
                      style={{
                        position: 'absolute',
                        right: 16,
                        top: '50%',
                        transform: 'translateY(-50%)',
                        background: 'rgba(0, 0, 0, 0.5)',
                        color: '#fff',
                        border: 'none',
                        padding: '12px 20px',
                        borderRadius: 8,
                        cursor: 'pointer',
                        fontSize: 24,
                      }}
                    >
                      ›
                    </button>
                    <div
                      style={{
                        position: 'absolute',
                        bottom: currentPhoto.caption ? 56 : 16,
                        left: '50%',
                        transform: 'translateX(-50%)',
                        background: 'rgba(0, 0, 0, 0.7)',
                        color: '#fff',
                        padding: '6px 12px',
                        borderRadius: 6,
                        fontSize: 13,
                      }}
                    >
                      {currentPhotoIndex + 1} / {thing.photos.length}
                    </div>
                  </>
                )}

                {/* Photo caption at bottom */}
                {currentPhoto.caption && (
                  <div
                    style={{
                      position: 'absolute',
                      bottom: 0,
                      left: 0,
                      right: 0,
                      background: 'rgba(0, 0, 0, 0.8)',
                      color: '#fff',
                      padding: '12px 16px',
                      fontSize: 14,
                    }}
                  >
                    {currentPhoto.caption}
                  </div>
                )}
              </div>

              {/* Right column: Content */}
              <div style={{ padding: 20, display: 'flex', flexDirection: 'column', gap: 16 }}>
                {/* Header with icon and delete button */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 20 }}>{icon}</span>
                    <span style={{ fontSize: 13, color: theme.textMuted }}>{kind?.name || 'Photo'}</span>
                  </div>
                  <div style={{ display: 'flex', gap: 4 }}>
                    <EditButton />
                    <DeleteButton />
                  </div>
                </div>

                {/* Post content */}
                {thing.content && (
                  <div style={{ paddingBottom: 12, borderBottom: `1px solid ${theme.border}` }}>
                    <Markdown content={thing.content} theme={theme} className="markdown-content" />
                  </div>
                )}

                {/* Metadata */}
                <div style={{ marginTop: 'auto' }}>
                  <p style={{ fontSize: 11, color: theme.textSubtle, margin: 0 }}>
                    {new Date(thing.created_at).toLocaleString()}
                  </p>
                </div>
              </div>
              </div>
            </div>
          </>
        )
      }

      // Single-column layout (feed view or mobile)
      return (
        <div
          onClick={handleCardClick}
          style={{
            background: theme.bgCard,
            borderRadius: 12,
            border: `1px solid ${theme.border}`,
            overflow: 'hidden',
            cursor: 'pointer',
            transition: 'box-shadow 0.15s',
          }}
          onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 4px 12px ${theme.shadow}`)}
          onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
        >
          <PhotoViewer />
          {/* Photo/Video Display */}
          <div style={{ position: 'relative', background: '#000' }}>
            {isVideo ? (
              <video
                src={apiUrl(`/api/photos/${currentPhoto.id}?size=thumb`)}
                controls
                style={{
                  width: '100%',
                  maxHeight: 400,
                  objectFit: 'contain',
                  display: 'block',
                }}
                onClick={(e) => {
                  e.stopPropagation()
                  if (isDetailView) setViewerOpen(true)
                  else handleCardClick()
                }}
              />
            ) : (
              <img
                src={apiUrl(`/api/photos/${currentPhoto.id}?size=thumb`)}
                alt={currentPhoto.caption || 'Photo'}
                onClick={(e) => {
                  e.stopPropagation()
                  if (isDetailView) setViewerOpen(true)
                  else handleCardClick()
                }}
                style={{
                  width: '100%',
                  maxHeight: 400,
                  objectFit: 'contain',
                  display: 'block',
                  cursor: isDetailView ? 'zoom-in' : 'pointer',
                }}
              />
            )}

            {/* Carousel Navigation */}
            {thing.photos!.length > 1 && (
              <>
                <button
                  type="button"
                  onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === 0 ? thing.photos!.length - 1 : prev - 1)) }}
                  style={{
                    position: 'absolute',
                    left: 8,
                    top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'rgba(0, 0, 0, 0.5)',
                    color: '#fff',
                    border: 'none',
                    padding: '8px 12px',
                    borderRadius: 4,
                    cursor: 'pointer',
                    fontSize: 18,
                  }}
                >
                  ‹
                </button>
                <button
                  type="button"
                  onClick={(e) => { e.stopPropagation(); setCurrentPhotoIndex((prev) => (prev === thing.photos!.length - 1 ? 0 : prev + 1)) }}
                  style={{
                    position: 'absolute',
                    right: 8,
                    top: '50%',
                    transform: 'translateY(-50%)',
                    background: 'rgba(0, 0, 0, 0.5)',
                    color: '#fff',
                    border: 'none',
                    padding: '8px 12px',
                    borderRadius: 4,
                    cursor: 'pointer',
                    fontSize: 18,
                  }}
                >
                  ›
                </button>
                <div
                  style={{
                    position: 'absolute',
                    bottom: 8,
                    right: 8,
                    background: 'rgba(0, 0, 0, 0.7)',
                    color: '#fff',
                    padding: '4px 8px',
                    borderRadius: 4,
                    fontSize: 12,
                  }}
                >
                  {currentPhotoIndex + 1} / {thing.photos.length}
                </div>
              </>
            )}
          </div>

          <div style={{ padding: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
              <div style={{ flex: 1 }}>
                {currentPhoto.caption && (
                  <p style={{ margin: '0 0 8px 0', fontSize: 13, color: theme.text }}>
                    {currentPhoto.caption}
                  </p>
                )}
                {thing.content && (
                  <div onClick={handleCardClick} style={{ cursor: 'pointer', marginBottom: 8 }}>
                    <Markdown content={thing.content} theme={theme} className="markdown-content" />
                  </div>
                )}
                <p style={{ fontSize: 11, color: theme.textSubtle, margin: 0 }}>
                  {new Date(thing.created_at).toLocaleString()}
                </p>
              </div>
              <EditButton />
            </div>
          </div>
        </div>
      )
    }

    // Handle single photo (metadata.url)
    const url = thing.metadata?.url as string | undefined
    const contentType = thing.metadata?.content_type as string | undefined
    const isVideo = contentType?.startsWith('video/')

    return (
      <div
        onClick={handleCardClick}
        style={{
          background: theme.bgCard,
          borderRadius: 12,
          border: `1px solid ${theme.border}`,
          overflow: 'hidden',
          cursor: 'pointer',
          transition: 'box-shadow 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 4px 12px ${theme.shadow}`)}
        onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
      >
        {url && (
          isVideo ? (
            <video
              src={url}
              controls
              style={{
                width: '100%',
                maxHeight: 400,
                objectFit: 'contain',
                background: '#000',
              }}
            />
          ) : (
            <img
              src={url}
              alt={thing.content || 'Photo'}
              style={{
                width: '100%',
                maxHeight: 400,
                objectFit: 'contain',
                background: theme.bgHover,
                cursor: 'pointer',
              }}
              onClick={() => window.open(url, '_blank')}
            />
          )
        )}
        <div style={{ padding: 12 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
            <div style={{ flex: 1 }}>
              {thing.content && (
                <div onClick={handleCardClick} style={{ cursor: 'pointer' }}>
                  <Markdown content={thing.content} theme={theme} className="markdown-content" />
                </div>
              )}
              <p style={{ fontSize: 11, color: theme.textSubtle, margin: thing.content ? '8px 0 0' : 0 }}>
                {new Date(thing.created_at).toLocaleString()}
              </p>
            </div>
            <EditButton />
          </div>
        </div>
      </div>
    )
  }

  // DEFAULT template - standard card
  return (
    <>
      <div
        onClick={handleCardClick}
        style={{
          padding: 16,
          background: theme.bgCard,
          borderRadius: 8,
          border: `1px solid ${theme.border}`,
          cursor: 'pointer',
          transition: 'box-shadow 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.boxShadow = `0 2px 8px ${theme.shadow}`)}
        onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
          <div style={{ flex: 1 }}>
            <span
              style={{
                display: 'inline-block',
                padding: '3px 10px',
                background: theme.bgMuted,
                color: theme.textMuted,
                borderRadius: 4,
                fontSize: 12,
                fontWeight: 500,
                marginBottom: 8,
              }}
            >
              {icon} {thing.type}
            </span>
            <Markdown content={thing.content} theme={theme} className="markdown-content" />
            <AttributesDisplay />
            <LinkedThingsDisplay />
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 8 }}>
              <span style={{ fontSize: 12, color: theme.textSubtle }}>
                {new Date(thing.created_at).toLocaleString()}
              </span>
              {thing.edited_at && (
                <EditedIndicator
                  editedAt={thing.edited_at}
                  onClick={() => setShowHistoryModal(true)}
                  theme={theme}
                />
              )}
            </div>
            {/* Reactions - only show if kind is reactable (defaults to true for backwards compatibility) */}
            {kind?.reactable !== false && (
              <div style={{ marginTop: 12 }} onClick={e => e.stopPropagation()}>
                <ReactionBar
                  targetId={thing.id}
                  targetType="thing"
                  reactions={reactions}
                  onReactionsChange={setReactions}
                  theme={theme}
                />
              </div>
            )}
          </div>
          <div style={{ display: 'flex', alignItems: 'center' }}>
            <BookmarkButton
              thingId={thing.id}
              isBookmarked={isBookmarked}
              onBookmarkChange={setIsBookmarked}
              theme={theme}
            />
            <EditButton />
          </div>
        </div>
      </div>

      {/* Edit History Modal */}
      {showHistoryModal && (
        <EditHistoryModal
          targetId={thing.id}
          targetType="thing"
          onClose={() => setShowHistoryModal(false)}
          theme={theme}
        />
      )}
    </>
  )
}

// Link Attribute Input Component
function LinkAttributeInput({
  attribute,
  value,
  onChange,
  theme,
}: {
  attribute: Attribute
  value: unknown
  onChange: (val: unknown) => void
  theme: Theme
}) {
  const [availableThings, setAvailableThings] = useState<Thing[]>([])
  const [searchFilter, setSearchFilter] = useState('')
  const [showDropdown, setShowDropdown] = useState(false)
  const [loading, setLoading] = useState(true)

  const linkedThingIds = Array.isArray(value) ? value : []

  useEffect(() => {
    const fetchThings = async () => {
      try {
        const res = await fetch(apiUrl('/api/things'), { credentials: 'include' })
        const data = await res.json()
        setAvailableThings(data || [])
      } catch (err) {
        console.error('Failed to fetch things:', err)
      } finally {
        setLoading(false)
      }
    }
    fetchThings()
  }, [])

  const filteredThings = availableThings.filter(
    (t: Thing) => !linkedThingIds.includes(t.id) &&
         (t.content?.toLowerCase().includes(searchFilter.toLowerCase()) ||
          t.type?.toLowerCase().includes(searchFilter.toLowerCase()))
  )

  const linkedThings = availableThings.filter((t: Thing) => linkedThingIds.includes(t.id))

  const labelStyle = { fontSize: 13, color: theme.textMuted, marginBottom: 4, display: 'block' }
  const inputStyle = {
    width: '100%',
    padding: '8px 12px',
    border: `1px solid ${theme.borderInput}`,
    borderRadius: 6,
    fontSize: 14,
    boxSizing: 'border-box' as const,
    background: theme.bgInput,
    color: theme.text,
  }

  return (
    <div>
      <label style={labelStyle}>
        {attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}
      </label>

      {/* Selected Things */}
      {linkedThings.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 8 }}>
          {linkedThings.map((thing: Thing) => (
            <div
              key={thing.id}
              style={{
                padding: '6px 10px',
                background: theme.bgMuted,
                borderRadius: 6,
                fontSize: 13,
                color: theme.text,
              }}
            >
              {thing.content || thing.type}
            </div>
          ))}
        </div>
      )}

      {/* Search and Dropdown */}
      <div style={{ position: 'relative' }}>
        <input
          type="text"
          placeholder={loading ? 'Loading...' : 'Search to add...'}
          value={searchFilter}
          onChange={e => setSearchFilter((e.target as HTMLInputElement).value)}
          onFocus={() => setShowDropdown(true)}
          disabled={loading}
          style={inputStyle}
        />

        {/* Dropdown */}
        {showDropdown && filteredThings.length > 0 && (
          <div
            style={{
              position: 'absolute',
              top: '100%',
              left: 0,
              right: 0,
              background: theme.bgCard,
              border: `1px solid ${theme.borderInput}`,
              borderTop: 'none',
              borderRadius: '0 0 6px 6px',
              maxHeight: 200,
              overflowY: 'auto',
              zIndex: 1000,
            }}
          >
            {filteredThings.map((thing: Thing) => (
              <div
                key={thing.id}
                onClick={() => {
                  onChange([...linkedThingIds, thing.id])
                  setSearchFilter('')
                  setShowDropdown(false)
                }}
                style={{
                  padding: '10px 12px',
                  cursor: 'pointer',
                  borderBottom: `1px solid ${theme.border}`,
                  fontSize: 14,
                  color: theme.text,
                }}
                onMouseEnter={e => (e.currentTarget.style.background = theme.bgHover)}
                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
              >
                {thing.content || thing.type}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// Attribute Input Component
function AttributeInput({
  attribute,
  value,
  onChange,
  theme,
}: {
  attribute: Attribute
  value: unknown
  onChange: (val: unknown) => void
  theme: Theme
}) {
  const labelStyle = { fontSize: 13, color: theme.textMuted, marginBottom: 4, display: 'block' }
  const inputStyle = {
    width: '100%',
    padding: '8px 12px',
    border: `1px solid ${theme.borderInput}`,
    borderRadius: 6,
    fontSize: 14,
    boxSizing: 'border-box' as const,
    background: theme.bgInput,
    color: theme.text,
  }

  switch (attribute.type) {
    case 'checkbox':
      return (
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, color: theme.text }}>
          <input
            type="checkbox"
            checked={Boolean(value)}
            onChange={e => onChange((e.target as HTMLInputElement).checked)}
          />
          {attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}
        </label>
      )
    case 'select':
      const options = attribute.options.split(',').map(o => o.trim()).filter(Boolean)
      return (
        <div>
          <label style={labelStyle}>{attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}</label>
          <select
            value={String(value || '')}
            onChange={e => onChange((e.target as HTMLSelectElement).value)}
            style={{ ...inputStyle, background: theme.bgInput }}
          >
            <option value="">Select...</option>
            {options.map(opt => (
              <option key={opt} value={opt}>{opt}</option>
            ))}
          </select>
        </div>
      )
    case 'number':
      return (
        <div>
          <label style={labelStyle}>{attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}</label>
          <input
            type="number"
            value={value as number || ''}
            onInput={e => onChange(Number((e.target as HTMLInputElement).value))}
            style={inputStyle}
          />
        </div>
      )
    case 'date':
      return (
        <div>
          <label style={labelStyle}>{attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}</label>
          <input
            type="date"
            value={String(value || '')}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            style={inputStyle}
          />
        </div>
      )
    case 'url':
      return (
        <div>
          <label style={labelStyle}>{attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}</label>
          <input
            type="url"
            value={String(value || '')}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            placeholder="https://..."
            style={inputStyle}
          />
        </div>
      )
    case 'link':
      return <LinkAttributeInput attribute={attribute} value={value} onChange={onChange} theme={theme} />
    default:
      return (
        <div>
          <label style={labelStyle}>{attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}</label>
          <input
            type="text"
            value={String(value || '')}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            style={inputStyle}
          />
        </div>
      )
  }
}

// Emoji Picker Component with categories like iPhone
function EmojiPicker({
  value,
  onChange,
  usedEmojis,
  theme,
}: {
  value: string
  onChange: (emoji: string) => void
  usedEmojis: string[]
  theme: Theme
}) {
  const [isOpen, setIsOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [selectedCategory, setSelectedCategory] = useState(0)

  // Filter emojis by search or show category
  const displayEmojis = search.trim()
    ? ALL_EMOJIS.filter(e => e.keywords.toLowerCase().includes(search.toLowerCase()))
    : EMOJI_CATEGORIES[selectedCategory].emojis

  return (
    <div style={{ position: 'relative' }}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        style={{
          width: 50,
          height: 42,
          border: `1px solid ${theme.borderInput}`,
          borderRadius: 6,
          background: theme.bgInput,
          fontSize: 20,
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        {value || '➕'}
      </button>

      {isOpen && (
        <div
          style={{
            position: 'absolute',
            top: '100%',
            left: 0,
            marginTop: 4,
            background: theme.bgCard,
            border: `1px solid ${theme.borderInput}`,
            borderRadius: 8,
            boxShadow: `0 4px 12px ${theme.shadowStrong}`,
            zIndex: 100,
            width: 320,
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          {/* Search */}
          <input
            type="text"
            value={search}
            onInput={e => setSearch((e.target as HTMLInputElement).value)}
            placeholder="Search emojis..."
            autoFocus
            style={{
              width: '100%',
              padding: '8px 12px',
              border: 'none',
              borderBottom: `1px solid ${theme.border}`,
              borderRadius: '8px 8px 0 0',
              fontSize: 14,
              boxSizing: 'border-box',
              outline: 'none',
              flexShrink: 0,
              background: theme.bgCard,
              color: theme.text,
            }}
          />

          {/* Category tabs */}
          {!search.trim() && (
            <div style={{ display: 'flex', borderBottom: `1px solid ${theme.border}`, padding: '4px 4px 0', gap: 2 }}>
              {EMOJI_CATEGORIES.map((cat, i) => (
                <button
                  key={cat.name}
                  type="button"
                  onClick={() => setSelectedCategory(i)}
                  title={cat.name}
                  style={{
                    flex: 1,
                    padding: '6px 2px',
                    border: 'none',
                    background: selectedCategory === i ? theme.bgMuted : 'transparent',
                    borderRadius: '4px 4px 0 0',
                    cursor: 'pointer',
                    fontSize: 16,
                    opacity: selectedCategory === i ? 1 : 0.6,
                  }}
                >
                  {cat.icon}
                </button>
              ))}
            </div>
          )}

          {/* Emojis grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(8, 1fr)',
              gap: 2,
              padding: 8,
              height: 220,
              overflowY: 'scroll',
              alignContent: 'start',
            }}
          >
            {displayEmojis.map(({ emoji }) => {
              const isUsed = usedEmojis.includes(emoji)
              return (
                <button
                  key={emoji}
                  type="button"
                  onClick={() => {
                    if (!isUsed) {
                      onChange(emoji)
                      setIsOpen(false)
                      setSearch('')
                    }
                  }}
                  style={{
                    width: 32,
                    height: 32,
                    border: 'none',
                    background: value === emoji ? theme.bgMuted : 'transparent',
                    borderRadius: 4,
                    cursor: isUsed ? 'not-allowed' : 'pointer',
                    opacity: isUsed ? 0.3 : 1,
                    fontSize: 20,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                  title={isUsed ? 'Already in use' : emoji}
                >
                  {emoji}
                </button>
              )
            })}
            {displayEmojis.length === 0 && (
              <div style={{ gridColumn: '1 / -1', padding: 12, textAlign: 'center', color: theme.textSubtle, fontSize: 13 }}>
                No emojis found
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// Kinds Management Panel
function KindsPanel({
  kinds,
  onCreateKind,
  onDeleteKind,
  setEditingKind,
  usedEmojis,
  theme,
  defaultKindId,
  onSetDefaultKind,
}: {
  kinds: Kind[]
  onCreateKind: (k: Partial<Kind>) => Promise<Kind | undefined>
  onDeleteKind: (id: string) => void
  setEditingKind: (k: Kind | null) => void
  usedEmojis: string[]
  theme: Theme
  defaultKindId: string | null
  onSetDefaultKind: (id: string | null) => void
}) {
  const [newName, setNewName] = useState('')
  const [newIcon, setNewIcon] = useState('')

  async function handleCreate(e: Event) {
    e.preventDefault()
    if (!newName.trim() || !newIcon) return
    await onCreateKind({ name: newName.toLowerCase(), icon: newIcon, attributes: [] })
    setNewName('')
    setNewIcon('')
  }

  return (
    <div>
      <h2 style={{ fontSize: 20, margin: '0 0 16px', color: theme.text }}>Kinds</h2>

      {/* Default Kind Selector */}
      <div style={{
        padding: 16,
        background: theme.bgCard,
        borderRadius: 12,
        border: `1px solid ${theme.border}`,
        marginBottom: 24,
      }}>
        <label style={{ display: 'block', fontSize: 14, color: theme.textMuted, marginBottom: 8 }}>
          Default Kind
        </label>
        <select
          value={defaultKindId || ''}
          onChange={e => onSetDefaultKind(e.currentTarget.value || null)}
          style={{
            width: '100%',
            padding: '10px 14px',
            border: `1px solid ${theme.borderInput}`,
            borderRadius: 6,
            background: theme.bgInput,
            color: theme.text,
            fontSize: 14,
          }}
        >
          <option value="">First in list</option>
          {kinds.map(k => (
            <option key={k.id} value={k.id}>{k.icon} {k.name}</option>
          ))}
        </select>
        <p style={{ fontSize: 12, color: theme.textMuted, marginTop: 8, marginBottom: 0 }}>
          This Kind will be pre-selected when creating new Things.
        </p>
      </div>

      {/* Create new kind */}
      <form onSubmit={handleCreate} style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
          <div>
            <label style={{ fontSize: 12, color: theme.textMuted, display: 'block', marginBottom: 4 }}>Icon</label>
            <EmojiPicker value={newIcon} onChange={setNewIcon} usedEmojis={usedEmojis} theme={theme} />
          </div>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 12, color: theme.textMuted, display: 'block', marginBottom: 4 }}>Name</label>
            <input
              type="text"
              value={newName}
              onInput={e => setNewName((e.target as HTMLInputElement).value)}
              placeholder="New kind name..."
              style={{ width: '100%', padding: '10px 14px', border: `1px solid ${theme.borderInput}`, borderRadius: 6, boxSizing: 'border-box', background: theme.bgInput, color: theme.text }}
            />
          </div>
          <button
            type="submit"
            disabled={!newName.trim() || !newIcon}
            style={{
              padding: '10px 20px',
              background: newName.trim() && newIcon ? theme.accent : theme.textDisabled,
              color: newName.trim() && newIcon ? theme.accentText : theme.textSubtle,
              border: 'none',
              borderRadius: 6,
              cursor: newName.trim() && newIcon ? 'pointer' : 'not-allowed',
              height: 42,
            }}
          >
            Add
          </button>
        </div>
      </form>

      {/* List of kinds */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
        {kinds.map(kind => (
          <div
            key={kind.id}
            style={{
              padding: 16,
              background: theme.bgCard,
              borderRadius: 8,
              border: defaultKindId === kind.id ? `2px solid ${theme.accent}` : `1px solid ${theme.border}`,
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
              <span
                style={{
                  display: 'inline-flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  width: 36,
                  height: 36,
                  background: theme.bgMuted,
                  borderRadius: 8,
                  fontSize: 18,
                }}
              >
                {kind.icon || '•'}
              </span>
              <div>
                <div style={{ fontWeight: 600, color: theme.text }}>
                  {kind.name}
                  {defaultKindId === kind.id && (
                    <span style={{ marginLeft: 8, fontSize: 11, color: theme.accent, fontWeight: 500 }}>DEFAULT</span>
                  )}
                </div>
                <div style={{ fontSize: 12, color: theme.textSubtle }}>
                  {kind.attributes?.length || 0} attributes
                  {kind.commentable && ' • replies enabled'}
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                onClick={() => setEditingKind(kind)}
                style={{
                  padding: '6px 12px',
                  background: theme.bgHover,
                  color: theme.text,
                  border: 'none',
                  borderRadius: 4,
                  cursor: 'pointer',
                }}
              >
                Edit
              </button>
              <button
                onClick={() => onDeleteKind(kind.id)}
                style={{
                  padding: '6px 12px',
                  background: theme.errorBg,
                  color: theme.errorText,
                  border: 'none',
                  borderRadius: 4,
                  cursor: 'pointer',
                }}
              >
                Delete
              </button>
            </div>
          </div>
        ))}
        {kinds.length === 0 && (
          <p style={{ color: theme.textMuted, textAlign: 'center', padding: 20 }}>
            No kinds yet. Create one above!
          </p>
        )}
      </div>
    </div>
  )
}

// API Key type
interface APIKey {
  id: string
  name: string
  key_prefix: string
  scopes: string[]
  last_used_at: string | null
  created_at: string
}

// Data Export/Import Panel
function DataExportPanel({
  theme,
  onImportComplete,
}: {
  theme: Theme
  onImportComplete: () => void
}) {
  const [importing, setImporting] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null)

  async function handleExport() {
    setExporting(true)
    setMessage(null)
    try {
      const res = await fetch(apiUrl('/api/export'), { credentials: 'include' })
      if (!res.ok) throw new Error('Export failed')

      const blob = await res.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `tenant-export-${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)

      setMessage({ type: 'success', text: 'Export downloaded successfully!' })
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to export data' })
    } finally {
      setExporting(false)
    }
  }

  async function handleImport(e: Event) {
    const input = e.target as HTMLInputElement
    const file = input.files?.[0]
    if (!file) return

    setImporting(true)
    setMessage(null)
    try {
      const text = await file.text()
      const res = await fetch(apiUrl('/api/import'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: text,
      })

      if (!res.ok) {
        const err = await res.json()
        throw new Error(err.error || 'Import failed')
      }

      const result = await res.json()
      setMessage({
        type: 'success',
        text: `Imported ${result.kindsCreated} kinds and ${result.thingsCreated} things (${result.kindsSkipped + result.thingsSkipped} skipped)`
      })
      onImportComplete()
    } catch (err) {
      setMessage({ type: 'error', text: err instanceof Error ? err.message : 'Failed to import data' })
    } finally {
      setImporting(false)
      input.value = '' // Reset file input
    }
  }

  return (
    <div>
      <h2 style={{ fontSize: 20, margin: '0 0 16px', color: theme.text }}>Data</h2>
      <p style={{ color: theme.textSecondary, marginBottom: 24, lineHeight: 1.6 }}>
        Export and import your things and kinds.
      </p>

      {/* Export Section */}
      <div style={{
        padding: 20,
        background: theme.bgCard,
        borderRadius: 12,
        border: `1px solid ${theme.border}`,
        marginBottom: 16,
      }}>
        <h3 style={{ fontSize: 16, margin: '0 0 8px', color: theme.text }}>Export</h3>
        <p style={{ fontSize: 14, color: theme.textMuted, margin: '0 0 16px' }}>
          Download all your things and kinds as a JSON file.
        </p>
        <button
          onClick={handleExport}
          disabled={exporting}
          style={{
            padding: '10px 20px',
            background: exporting ? theme.textDisabled : theme.accent,
            color: exporting ? theme.textSubtle : theme.accentText,
            border: 'none',
            borderRadius: 6,
            cursor: exporting ? 'not-allowed' : 'pointer',
            fontSize: 14,
          }}
        >
          {exporting ? 'Exporting...' : 'Download Export'}
        </button>
      </div>

      {/* Import Section */}
      <div style={{
        padding: 20,
        background: theme.bgCard,
        borderRadius: 12,
        border: `1px solid ${theme.border}`,
        marginBottom: 16,
      }}>
        <h3 style={{ fontSize: 16, margin: '0 0 8px', color: theme.text }}>Import</h3>
        <p style={{ fontSize: 14, color: theme.textMuted, margin: '0 0 16px' }}>
          Import things and kinds from a tenant export file. Duplicates will be skipped.
        </p>
        <label style={{
          display: 'inline-block',
          padding: '10px 20px',
          background: importing ? theme.textDisabled : theme.bgHover,
          color: importing ? theme.textSubtle : theme.text,
          border: `1px solid ${theme.border}`,
          borderRadius: 6,
          cursor: importing ? 'not-allowed' : 'pointer',
          fontSize: 14,
        }}>
          {importing ? 'Importing...' : 'Choose File'}
          <input
            type="file"
            accept=".json"
            onChange={handleImport}
            disabled={importing}
            style={{ display: 'none' }}
          />
        </label>
      </div>

      {/* Status Message */}
      {message && (
        <div style={{
          padding: 12,
          background: message.type === 'success' ? theme.success : theme.errorBg,
          color: message.type === 'success' ? theme.successText : theme.errorText,
          borderRadius: 8,
          fontSize: 14,
        }}>
          {message.text}
        </div>
      )}
    </div>
  )
}

// API Keys Panel
function APIKeysPanel({ theme }: { theme: Theme }) {
  const [apiKeys, setApiKeys] = useState<APIKey[]>([])
  const [availableScopes, setAvailableScopes] = useState<string[]>([])
  const [showCreateKey, setShowCreateKey] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyScopes, setNewKeyScopes] = useState<string[]>([])
  const [isAdminKey, setIsAdminKey] = useState(true)
  const [createdKey, setCreatedKey] = useState<string | null>(null)
  const [keyCopied, setKeyCopied] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null)

  useEffect(() => {
    fetchAPIKeys()
  }, [])

  async function fetchAPIKeys() {
    try {
      const res = await fetch(apiUrl('/api/keys'), { credentials: 'include' })
      if (res.ok) {
        const data = await res.json()
        setApiKeys(data.keys || [])
        setAvailableScopes(data.availableScopes || [])
      }
    } catch (err) {
      console.error('Failed to fetch API keys:', err)
    }
  }

  async function createAPIKey(e: Event) {
    e.preventDefault()
    if (!newKeyName.trim()) return

    try {
      const res = await fetch(apiUrl('/api/keys'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          name: newKeyName,
          scopes: isAdminKey ? [] : newKeyScopes,
        }),
      })

      if (!res.ok) throw new Error('Failed to create key')

      const data = await res.json()
      setCreatedKey(data.key)
      setNewKeyName('')
      setNewKeyScopes([])
      setIsAdminKey(true)
      setShowCreateKey(false)
      fetchAPIKeys()
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to create API key' })
    }
  }

  async function deleteAPIKey(id: string) {
    if (!confirm('Delete this API key? This cannot be undone.')) return

    try {
      await fetch(apiUrl(`/api/keys/${id}`), {
        method: 'DELETE',
        credentials: 'include',
      })
      fetchAPIKeys()
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to delete API key' })
    }
  }

  function copyKey() {
    if (createdKey) {
      navigator.clipboard.writeText(createdKey)
      setKeyCopied(true)
      setTimeout(() => setKeyCopied(false), 2000)
    }
  }

  return (
    <div>
      <h2 style={{ fontSize: 20, margin: '0 0 16px', color: theme.text }}>API Keys</h2>
      <p style={{ color: theme.textSecondary, marginBottom: 24, lineHeight: 1.6 }}>
        Create API keys for programmatic access. Keys can have full admin access or be scoped to specific permissions.
      </p>

      {/* Status Message */}
      {message && (
        <div style={{
          padding: 12,
          background: message.type === 'success' ? theme.success : theme.errorBg,
          color: message.type === 'success' ? theme.successText : theme.errorText,
          borderRadius: 8,
          fontSize: 14,
          marginBottom: 16,
        }}>
          {message.text}
        </div>
      )}

      {/* Created Key Display */}
      {createdKey && (
        <div style={{
          padding: 16,
          background: theme.success,
          borderRadius: 12,
          marginBottom: 16,
        }}>
          <div style={{ fontWeight: 600, marginBottom: 8, color: theme.successText }}>
            API Key Created - Save this now!
          </div>
          <div style={{
            display: 'flex',
            gap: 8,
            alignItems: 'center',
            background: theme.bgCard,
            padding: 12,
            borderRadius: 6,
            fontFamily: 'monospace',
            fontSize: 14,
            wordBreak: 'break-all',
          }}>
            <code style={{ flex: 1, color: theme.text }}>{createdKey}</code>
            <button
              onClick={copyKey}
              style={{
                padding: '6px 12px',
                background: theme.accent,
                color: theme.accentText,
                border: 'none',
                borderRadius: 4,
                cursor: 'pointer',
                fontSize: 12,
              }}
            >
              {keyCopied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <button
            onClick={() => setCreatedKey(null)}
            style={{
              marginTop: 12,
              padding: '8px 16px',
              background: 'transparent',
              color: theme.successText,
              border: `1px solid ${theme.successText}`,
              borderRadius: 6,
              cursor: 'pointer',
              fontSize: 13,
            }}
          >
            I've saved the key
          </button>
        </div>
      )}

      {/* Create New Key */}
      <div style={{
        padding: 20,
        background: theme.bgCard,
        borderRadius: 12,
        border: `1px solid ${theme.border}`,
        marginBottom: 16,
      }}>
        {!showCreateKey ? (
          <button
            onClick={() => setShowCreateKey(true)}
            style={{
              padding: '10px 20px',
              background: theme.accent,
              color: theme.accentText,
              border: 'none',
              borderRadius: 6,
              cursor: 'pointer',
              fontSize: 14,
            }}
          >
            + Create New API Key
          </button>
        ) : (
          <form onSubmit={createAPIKey}>
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', fontSize: 14, color: theme.textMuted, marginBottom: 6 }}>
                Key Name
              </label>
              <input
                type="text"
                value={newKeyName}
                onInput={e => setNewKeyName((e.target as HTMLInputElement).value)}
                placeholder="e.g., Chrome Extension, Mobile App..."
                style={{
                  width: '100%',
                  padding: '10px 14px',
                  border: `1px solid ${theme.borderInput}`,
                  borderRadius: 6,
                  background: theme.bgInput,
                  color: theme.text,
                  fontSize: 14,
                  boxSizing: 'border-box',
                }}
              />
            </div>

            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={isAdminKey}
                  onChange={e => setIsAdminKey((e.target as HTMLInputElement).checked)}
                />
                <span style={{ color: theme.text }}>Admin key (all permissions)</span>
              </label>
            </div>

            {!isAdminKey && (
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'block', fontSize: 14, color: theme.textMuted, marginBottom: 8 }}>
                  Scopes
                </label>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8 }}>
                  {availableScopes.map(scope => (
                    <label
                      key={scope}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: 6,
                        padding: '6px 10px',
                        background: newKeyScopes.includes(scope) ? theme.accent : theme.bgHover,
                        color: newKeyScopes.includes(scope) ? theme.accentText : theme.text,
                        borderRadius: 6,
                        cursor: 'pointer',
                        fontSize: 13,
                      }}
                    >
                      <input
                        type="checkbox"
                        checked={newKeyScopes.includes(scope)}
                        onChange={e => {
                          if ((e.target as HTMLInputElement).checked) {
                            setNewKeyScopes([...newKeyScopes, scope])
                          } else {
                            setNewKeyScopes(newKeyScopes.filter(s => s !== scope))
                          }
                        }}
                        style={{ display: 'none' }}
                      />
                      {scope}
                    </label>
                  ))}
                </div>
              </div>
            )}

            <div style={{ display: 'flex', gap: 8 }}>
              <button
                type="submit"
                disabled={!newKeyName.trim() || (!isAdminKey && newKeyScopes.length === 0)}
                style={{
                  padding: '10px 20px',
                  background: newKeyName.trim() && (isAdminKey || newKeyScopes.length > 0)
                    ? theme.accent
                    : theme.textDisabled,
                  color: newKeyName.trim() && (isAdminKey || newKeyScopes.length > 0)
                    ? theme.accentText
                    : theme.textSubtle,
                  border: 'none',
                  borderRadius: 6,
                  cursor: newKeyName.trim() && (isAdminKey || newKeyScopes.length > 0)
                    ? 'pointer'
                    : 'not-allowed',
                  fontSize: 14,
                }}
              >
                Create Key
              </button>
              <button
                type="button"
                onClick={() => {
                  setShowCreateKey(false)
                  setNewKeyName('')
                  setNewKeyScopes([])
                  setIsAdminKey(true)
                }}
                style={{
                  padding: '10px 20px',
                  background: theme.bgHover,
                  color: theme.textMuted,
                  border: 'none',
                  borderRadius: 6,
                  cursor: 'pointer',
                  fontSize: 14,
                }}
              >
                Cancel
              </button>
            </div>
          </form>
        )}
      </div>

      {/* Existing Keys */}
      {apiKeys.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {apiKeys.map(key => (
            <div
              key={key.id}
              style={{
                padding: 16,
                background: theme.bgCard,
                borderRadius: 8,
                border: `1px solid ${theme.border}`,
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: 12,
              }}
            >
              <div>
                <div style={{ fontWeight: 600, color: theme.text, marginBottom: 4 }}>
                  {key.name}
                </div>
                <div style={{ fontSize: 12, color: theme.textMuted }}>
                  <code style={{ background: theme.bgMuted, padding: '2px 6px', borderRadius: 4 }}>
                    {key.key_prefix}...
                  </code>
                  {' • '}
                  {key.scopes.length === availableScopes.length ? 'Admin' : `${key.scopes.length} scopes`}
                  {key.last_used_at && (
                    <>
                      {' • Last used '}
                      {new Date(key.last_used_at).toLocaleDateString()}
                    </>
                  )}
                </div>
              </div>
              <button
                onClick={() => deleteAPIKey(key.id)}
                style={{
                  padding: '6px 12px',
                  background: theme.errorBg,
                  color: theme.errorText,
                  border: 'none',
                  borderRadius: 4,
                  cursor: 'pointer',
                  fontSize: 13,
                }}
              >
                Delete
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ==================== INTEGRATIONS PANEL ====================

interface FilterCondition {
  field: string
  op: string
  value: any
}

interface FilterConfig {
  kinds?: string[]
  condition_groups?: FilterCondition[][]
}

interface OutboundWebhook {
  id: string
  name: string
  url: string
  event_types: string[]
  signing_secret?: string
  filter_config?: FilterConfig
  enabled: boolean
  created_at: string
  updated_at: string
}

interface InboundWebhook {
  id: string
  name: string
  source_system: string
  default_thing_type: string
  default_visibility: string
  token_prefix: string
  secret_token?: string
  enabled: boolean
  created_at: string
  updated_at: string
}

interface WebhookTestResult {
  success: boolean
  status_code?: number
  response_time_ms?: number
  error?: string
}

function IntegrationsPanel({ theme, kinds }: { theme: Theme, kinds: Kind[] }) {
  const [outboundWebhooks, setOutboundWebhooks] = useState<OutboundWebhook[]>([])
  const [inboundWebhooks, setInboundWebhooks] = useState<InboundWebhook[]>([])
  const [loading, setLoading] = useState(true)
  const [showCreateOutbound, setShowCreateOutbound] = useState(false)
  const [showCreateInbound, setShowCreateInbound] = useState(false)
  const [testingWebhook, setTestingWebhook] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<{ id: string, result: WebhookTestResult } | null>(null)
  const [expandedOutbound, setExpandedOutbound] = useState<string | null>(null)
  const [expandedInbound, setExpandedInbound] = useState<string | null>(null)
  const [revealedToken, setRevealedToken] = useState<string | null>(null)
  const [copiedId, setCopiedId] = useState<string | null>(null)

  useEffect(() => {
    fetchWebhooks()
  }, [])

  async function fetchWebhooks() {
    setLoading(true)
    try {
      const [outboundRes, inboundRes] = await Promise.all([
        fetch(apiUrl('/api/webhooks'), { credentials: 'include' }),
        fetch(apiUrl('/api/webhooks/inbound'), { credentials: 'include' }),
      ])

      if (outboundRes.ok) {
        const data = await outboundRes.json()
        setOutboundWebhooks(Array.isArray(data) ? data : [])
      }

      if (inboundRes.ok) {
        const data = await inboundRes.json()
        setInboundWebhooks(Array.isArray(data) ? data : [])
      }
    } catch (err) {
      console.error('Failed to fetch webhooks:', err)
    } finally {
      setLoading(false)
    }
  }

  async function toggleOutboundEnabled(webhook: OutboundWebhook) {
    try {
      const res = await fetch(apiUrl(`/api/webhooks/${webhook.id}`), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ enabled: !webhook.enabled }),
      })
      if (res.ok) {
        setOutboundWebhooks(prev => prev.map(w =>
          w.id === webhook.id ? { ...w, enabled: !w.enabled } : w
        ))
      }
    } catch (err) {
      console.error('Failed to toggle webhook:', err)
    }
  }

  async function toggleInboundEnabled(webhook: InboundWebhook) {
    try {
      const res = await fetch(apiUrl(`/api/webhooks/inbound/${webhook.id}`), {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ enabled: !webhook.enabled }),
      })
      if (res.ok) {
        setInboundWebhooks(prev => prev.map(w =>
          w.id === webhook.id ? { ...w, enabled: !w.enabled } : w
        ))
      }
    } catch (err) {
      console.error('Failed to toggle webhook:', err)
    }
  }

  async function deleteOutboundWebhook(id: string) {
    if (!confirm('Delete this webhook? This cannot be undone.')) return
    try {
      const res = await fetch(apiUrl(`/api/webhooks/${id}`), {
        method: 'DELETE',
        credentials: 'include',
      })
      if (res.ok) {
        setOutboundWebhooks(prev => prev.filter(w => w.id !== id))
      }
    } catch (err) {
      console.error('Failed to delete webhook:', err)
    }
  }

  async function deleteInboundWebhook(id: string) {
    if (!confirm('Delete this webhook? This cannot be undone.')) return
    try {
      const res = await fetch(apiUrl(`/api/webhooks/inbound/${id}`), {
        method: 'DELETE',
        credentials: 'include',
      })
      if (res.ok) {
        setInboundWebhooks(prev => prev.filter(w => w.id !== id))
      }
    } catch (err) {
      console.error('Failed to delete webhook:', err)
    }
  }

  async function testWebhook(id: string) {
    setTestingWebhook(id)
    setTestResult(null)
    try {
      const start = Date.now()
      const res = await fetch(apiUrl(`/api/webhooks/${id}/test`), {
        method: 'POST',
        credentials: 'include',
      })
      const elapsed = Date.now() - start
      const data = await res.json()
      setTestResult({
        id,
        result: {
          success: res.ok && data.success,
          status_code: data.status_code,
          response_time_ms: elapsed,
          error: data.error,
        }
      })
      // Auto-dismiss after 10 seconds
      setTimeout(() => setTestResult(prev => prev?.id === id ? null : prev), 10000)
    } catch (err) {
      setTestResult({
        id,
        result: { success: false, error: 'Failed to send test' }
      })
    } finally {
      setTestingWebhook(null)
    }
  }

  function copyToClipboard(text: string, id: string) {
    navigator.clipboard.writeText(text)
    setCopiedId(id)
    setTimeout(() => setCopiedId(null), 2000)
  }

  const cardStyle = {
    background: theme.bgCard,
    border: `1px solid ${theme.border}`,
    borderRadius: 8,
    padding: 16,
    marginBottom: 12,
  }

  const toggleStyle = (enabled: boolean) => ({
    width: 40,
    height: 22,
    borderRadius: 11,
    background: enabled ? theme.accent : theme.bgMuted,
    border: 'none',
    cursor: 'pointer',
    position: 'relative' as const,
    transition: 'background 0.2s',
  })

  const toggleKnobStyle = (enabled: boolean) => ({
    position: 'absolute' as const,
    top: 2,
    left: enabled ? 20 : 2,
    width: 18,
    height: 18,
    borderRadius: 9,
    background: 'white',
    transition: 'left 0.2s',
  })

  if (loading) {
    return <div style={{ color: theme.textMuted }}>Loading integrations...</div>
  }

  return (
    <div>
      {/* Outbound Webhooks Section */}
      <div style={{ marginBottom: 32 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ margin: 0, color: theme.text, fontSize: 16, fontWeight: 600 }}>
            Outbound Webhooks
          </h3>
          <button
            onClick={() => setShowCreateOutbound(true)}
            style={{
              padding: '6px 12px',
              background: theme.bgHover,
              color: theme.text,
              border: `1px solid ${theme.border}`,
              borderRadius: 6,
              cursor: 'pointer',
              fontSize: 13,
            }}
          >
            + Add
          </button>
        </div>

        {outboundWebhooks.length === 0 ? (
          <div style={{ ...cardStyle, textAlign: 'center', color: theme.textMuted }}>
            No outbound webhooks configured.
            <br />
            <span style={{ fontSize: 13 }}>Outbound webhooks send events to external URLs when things happen.</span>
          </div>
        ) : (
          outboundWebhooks.map(webhook => (
            <div key={webhook.id} style={cardStyle}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <span style={{ fontWeight: 600, color: theme.text }}>
                      {webhook.name || 'Unnamed webhook'}
                    </span>
                    <button
                      onClick={() => toggleOutboundEnabled(webhook)}
                      style={toggleStyle(webhook.enabled)}
                      title={webhook.enabled ? 'Enabled' : 'Disabled'}
                    >
                      <div style={toggleKnobStyle(webhook.enabled)} />
                    </button>
                  </div>
                  <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 8, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {webhook.url}
                  </div>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {webhook.event_types?.map(evt => (
                      <span
                        key={evt}
                        style={{
                          fontSize: 11,
                          padding: '2px 8px',
                          background: theme.bgMuted,
                          color: theme.textMuted,
                          borderRadius: 12,
                        }}
                      >
                        {evt}
                      </span>
                    ))}
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <button
                    onClick={() => testWebhook(webhook.id)}
                    disabled={testingWebhook === webhook.id}
                    style={{
                      padding: '6px 12px',
                      background: 'transparent',
                      color: theme.accent,
                      border: `1px solid ${theme.accent}`,
                      borderRadius: 4,
                      cursor: testingWebhook === webhook.id ? 'wait' : 'pointer',
                      fontSize: 12,
                      opacity: testingWebhook === webhook.id ? 0.6 : 1,
                    }}
                  >
                    {testingWebhook === webhook.id ? '...' : 'Test'}
                  </button>
                  <button
                    onClick={() => setExpandedOutbound(expandedOutbound === webhook.id ? null : webhook.id)}
                    style={{
                      padding: '6px 10px',
                      background: 'transparent',
                      color: theme.textMuted,
                      border: 'none',
                      cursor: 'pointer',
                      fontSize: 14,
                    }}
                  >
                    {expandedOutbound === webhook.id ? '▲' : '▼'}
                  </button>
                  <button
                    onClick={() => deleteOutboundWebhook(webhook.id)}
                    style={{
                      padding: '6px 10px',
                      background: 'transparent',
                      color: theme.error,
                      border: 'none',
                      cursor: 'pointer',
                      fontSize: 13,
                    }}
                  >
                    Delete
                  </button>
                </div>
              </div>

              {/* Test Result */}
              {testResult?.id === webhook.id && (
                <div
                  style={{
                    marginTop: 12,
                    padding: 12,
                    background: testResult.result.success ? 'rgba(34, 197, 94, 0.1)' : 'rgba(239, 68, 68, 0.1)',
                    borderRadius: 6,
                    display: 'flex',
                    alignItems: 'center',
                    gap: 8,
                  }}
                >
                  <span style={{ fontSize: 16 }}>{testResult.result.success ? '✓' : '✗'}</span>
                  <span style={{ fontSize: 13, color: testResult.result.success ? '#22c55e' : theme.error }}>
                    {testResult.result.success
                      ? `Success • ${testResult.result.status_code} • ${testResult.result.response_time_ms}ms`
                      : testResult.result.error || 'Failed'}
                  </span>
                  <button
                    onClick={() => setTestResult(null)}
                    style={{
                      marginLeft: 'auto',
                      background: 'transparent',
                      border: 'none',
                      color: theme.textMuted,
                      cursor: 'pointer',
                      fontSize: 12,
                    }}
                  >
                    Dismiss
                  </button>
                </div>
              )}

              {/* Expanded Details */}
              {expandedOutbound === webhook.id && (
                <div style={{ marginTop: 16, paddingTop: 16, borderTop: `1px solid ${theme.border}` }}>
                  <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 8 }}>
                    <strong>URL:</strong> {webhook.url}
                  </div>
                  {webhook.signing_secret && (
                    <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 8 }}>
                      <strong>Signing Secret:</strong>{' '}
                      <code style={{ background: theme.bgMuted, padding: '2px 6px', borderRadius: 4 }}>
                        {revealedToken === webhook.id ? webhook.signing_secret : '••••••••••••'}
                      </code>
                      <button
                        onClick={() => setRevealedToken(revealedToken === webhook.id ? null : webhook.id)}
                        style={{
                          marginLeft: 8,
                          background: 'transparent',
                          border: 'none',
                          color: theme.accent,
                          cursor: 'pointer',
                          fontSize: 12,
                        }}
                      >
                        {revealedToken === webhook.id ? 'Hide' : 'Reveal'}
                      </button>
                    </div>
                  )}
                  {(webhook.filter_config?.kinds?.length || webhook.filter_config?.condition_groups?.length) && (
                    <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 8 }}>
                      <strong>Filter:</strong>
                      {webhook.filter_config?.kinds?.length && (
                        <span> Kind in [{webhook.filter_config.kinds.join(', ')}]</span>
                      )}
                      {webhook.filter_config?.condition_groups?.length && webhook.filter_config.condition_groups[0]?.length && (
                        <span>
                          {webhook.filter_config.kinds?.length ? ' AND ' : ' '}
                          {webhook.filter_config.condition_groups[0].map((c, i) => (
                            <span key={i}>
                              {i > 0 && ' AND '}
                              {c.field} {c.op} {c.op !== 'exists' ? JSON.stringify(c.value) : ''}
                            </span>
                          ))}
                        </span>
                      )}
                    </div>
                  )}
                  <div style={{ fontSize: 12, color: theme.textMuted }}>
                    Created: {new Date(webhook.created_at).toLocaleDateString()}
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Inbound Webhooks Section */}
      <div>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ margin: 0, color: theme.text, fontSize: 16, fontWeight: 600 }}>
            Inbound Webhooks
          </h3>
          <button
            onClick={() => setShowCreateInbound(true)}
            style={{
              padding: '6px 12px',
              background: theme.bgHover,
              color: theme.text,
              border: `1px solid ${theme.border}`,
              borderRadius: 6,
              cursor: 'pointer',
              fontSize: 13,
            }}
          >
            + Add
          </button>
        </div>

        {inboundWebhooks.length === 0 ? (
          <div style={{ ...cardStyle, textAlign: 'center', color: theme.textMuted }}>
            No inbound webhooks configured.
            <br />
            <span style={{ fontSize: 13 }}>Inbound webhooks let external services create things in your account.</span>
          </div>
        ) : (
          inboundWebhooks.map(webhook => (
            <div key={webhook.id} style={cardStyle}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 12 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                    <span style={{ fontWeight: 600, color: theme.text }}>
                      {webhook.name}
                    </span>
                    <span
                      style={{
                        fontSize: 11,
                        padding: '2px 8px',
                        background: theme.bgMuted,
                        color: theme.textMuted,
                        borderRadius: 12,
                      }}
                    >
                      {webhook.source_system}
                    </span>
                    <button
                      onClick={() => toggleInboundEnabled(webhook)}
                      style={toggleStyle(webhook.enabled)}
                      title={webhook.enabled ? 'Enabled' : 'Disabled'}
                    >
                      <div style={toggleKnobStyle(webhook.enabled)} />
                    </button>
                  </div>
                  <div style={{ fontSize: 13, color: theme.textMuted }}>
                    Creates: {webhook.default_thing_type} ({webhook.default_visibility})
                  </div>
                </div>
                <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                  <button
                    onClick={() => setExpandedInbound(expandedInbound === webhook.id ? null : webhook.id)}
                    style={{
                      padding: '6px 10px',
                      background: 'transparent',
                      color: theme.textMuted,
                      border: 'none',
                      cursor: 'pointer',
                      fontSize: 14,
                    }}
                  >
                    {expandedInbound === webhook.id ? '▲' : '▼'}
                  </button>
                  <button
                    onClick={() => deleteInboundWebhook(webhook.id)}
                    style={{
                      padding: '6px 10px',
                      background: 'transparent',
                      color: theme.error,
                      border: 'none',
                      cursor: 'pointer',
                      fontSize: 13,
                    }}
                  >
                    Delete
                  </button>
                </div>
              </div>

              {/* Expanded Details */}
              {expandedInbound === webhook.id && (
                <div style={{ marginTop: 16, paddingTop: 16, borderTop: `1px solid ${theme.border}` }}>
                  <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 12 }}>
                    <strong>Endpoint:</strong>
                    <div style={{ marginTop: 4, display: 'flex', alignItems: 'center', gap: 8 }}>
                      <code
                        style={{
                          background: theme.bgMuted,
                          padding: '6px 10px',
                          borderRadius: 4,
                          fontSize: 12,
                          wordBreak: 'break-all',
                          flex: 1,
                        }}
                      >
                        POST {window.location.origin}/api/webhooks/receive/{webhook.id}?token=...
                      </code>
                      <button
                        onClick={() => {
                          const url = `${window.location.origin}/api/webhooks/receive/${webhook.id}?token=${webhook.secret_token || webhook.token_prefix + '...'}`
                          copyToClipboard(url, 'url-' + webhook.id)
                        }}
                        style={{
                          padding: '6px 10px',
                          background: theme.bgHover,
                          color: copiedId === 'url-' + webhook.id ? '#22c55e' : theme.text,
                          border: `1px solid ${theme.border}`,
                          borderRadius: 4,
                          cursor: 'pointer',
                          fontSize: 12,
                        }}
                      >
                        {copiedId === 'url-' + webhook.id ? 'Copied!' : 'Copy'}
                      </button>
                    </div>
                  </div>
                  <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 8 }}>
                    <strong>Token:</strong>{' '}
                    <code style={{ background: theme.bgMuted, padding: '2px 6px', borderRadius: 4 }}>
                      {revealedToken === 'inbound-' + webhook.id
                        ? (webhook.secret_token || webhook.token_prefix + '...')
                        : webhook.token_prefix + '••••••••'}
                    </code>
                    <button
                      onClick={() => setRevealedToken(revealedToken === 'inbound-' + webhook.id ? null : 'inbound-' + webhook.id)}
                      style={{
                        marginLeft: 8,
                        background: 'transparent',
                        border: 'none',
                        color: theme.accent,
                        cursor: 'pointer',
                        fontSize: 12,
                      }}
                    >
                      {revealedToken === 'inbound-' + webhook.id ? 'Hide' : 'Reveal'}
                    </button>
                  </div>
                  <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 12 }}>
                    <strong>Example curl:</strong>
                    <pre style={{
                      marginTop: 4,
                      background: theme.bgMuted,
                      padding: 12,
                      borderRadius: 4,
                      fontSize: 11,
                      overflow: 'auto',
                      whiteSpace: 'pre-wrap',
                      wordBreak: 'break-all',
                    }}>
{`curl -X POST "${window.location.origin}/api/webhooks/receive/${webhook.id}?token=${webhook.secret_token || 'YOUR_TOKEN'}" \\
  -H "Content-Type: application/json" \\
  -d '{
    "content": "Hello from my automation!",
    "metadata": {
      "source": "zapier",
      "priority": "high"
    },
    "external_id": "unique-123"
  }'`}
                    </pre>
                    <button
                      onClick={() => {
                        const curl = `curl -X POST "${window.location.origin}/api/webhooks/receive/${webhook.id}?token=${webhook.secret_token || 'YOUR_TOKEN'}" \\\n  -H "Content-Type: application/json" \\\n  -d '{"content": "Hello from my automation!", "external_id": "unique-123"}'`
                        copyToClipboard(curl, 'curl-' + webhook.id)
                      }}
                      style={{
                        marginTop: 8,
                        padding: '6px 12px',
                        background: theme.bgHover,
                        color: copiedId === 'curl-' + webhook.id ? '#22c55e' : theme.text,
                        border: `1px solid ${theme.border}`,
                        borderRadius: 4,
                        cursor: 'pointer',
                        fontSize: 12,
                      }}
                    >
                      {copiedId === 'curl-' + webhook.id ? 'Copied!' : 'Copy curl'}
                    </button>
                  </div>
                  <div style={{ fontSize: 13, color: theme.textMuted, marginBottom: 8 }}>
                    <strong>Payload fields:</strong>
                    <ul style={{ margin: '8px 0 0 0', paddingLeft: 20, fontSize: 12 }}>
                      <li><code>content</code> - The text content of the Thing (required)</li>
                      <li><code>metadata</code> - Optional JSON object with additional attributes</li>
                      <li><code>external_id</code> - Optional unique ID for deduplication</li>
                    </ul>
                  </div>
                  <div style={{ fontSize: 12, color: theme.textMuted }}>
                    Created: {new Date(webhook.created_at).toLocaleDateString()}
                  </div>
                </div>
              )}
            </div>
          ))
        )}
      </div>

      {/* Create Outbound Modal */}
      {showCreateOutbound && (
        <CreateOutboundWebhookModal
          theme={theme}
          kinds={kinds}
          onClose={() => setShowCreateOutbound(false)}
          onCreate={(webhook) => {
            setOutboundWebhooks(prev => [...prev, webhook])
            setShowCreateOutbound(false)
          }}
        />
      )}

      {/* Create Inbound Modal */}
      {showCreateInbound && (
        <CreateInboundWebhookModal
          theme={theme}
          kinds={kinds}
          onClose={() => setShowCreateInbound(false)}
          onCreate={(webhook) => {
            setInboundWebhooks(prev => [...prev, webhook])
            setShowCreateInbound(false)
            // Show the new webhook expanded to reveal the token
            setExpandedInbound(webhook.id)
            setRevealedToken('inbound-' + webhook.id)
          }}
        />
      )}
    </div>
  )
}

// Create Outbound Webhook Modal
function CreateOutboundWebhookModal({
  theme,
  kinds,
  onClose,
  onCreate,
}: {
  theme: Theme
  kinds: Kind[]
  onClose: () => void
  onCreate: (webhook: OutboundWebhook) => void
}) {
  const [name, setName] = useState('')
  const [url, setUrl] = useState('')
  const [eventTypes, setEventTypes] = useState<string[]>(['thing.created'])
  const [filterKinds, setFilterKinds] = useState<string[]>([])
  const [conditions, setConditions] = useState<FilterCondition[]>([])
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const availableEvents = [
    { id: 'thing.created', label: 'Thing created' },
    { id: 'thing.updated', label: 'Thing updated' },
    { id: 'thing.deleted', label: 'Thing deleted' },
    { id: 'comment.created', label: 'Comment created' },
  ]

  const operators = [
    { id: 'eq', label: '=' },
    { id: 'neq', label: '≠' },
    { id: 'gt', label: '>' },
    { id: 'gte', label: '≥' },
    { id: 'lt', label: '<' },
    { id: 'lte', label: '≤' },
    { id: 'contains', label: 'contains' },
    { id: 'exists', label: 'exists' },
  ]

  function addCondition() {
    setConditions([...conditions, { field: '', op: 'eq', value: '' }])
  }

  function updateCondition(index: number, updates: Partial<FilterCondition>) {
    setConditions(conditions.map((c, i) => i === index ? { ...c, ...updates } : c))
  }

  function removeCondition(index: number) {
    setConditions(conditions.filter((_, i) => i !== index))
  }

  function parseConditionValue(value: string): any {
    // Try to parse as JSON (number, boolean, etc.)
    try {
      return JSON.parse(value)
    } catch {
      return value // Keep as string if not valid JSON
    }
  }

  async function handleSubmit(e: Event) {
    e.preventDefault()
    if (!url.trim()) return

    setSaving(true)
    setError(null)

    // Build filter_config if kinds or conditions are set
    const validConditions = conditions.filter(c => c.field.trim())
    const filter_config: FilterConfig | undefined = (filterKinds.length > 0 || validConditions.length > 0)
      ? {
          kinds: filterKinds.length > 0 ? filterKinds : undefined,
          condition_groups: validConditions.length > 0
            ? [validConditions.map(c => ({
                field: c.field.trim(),
                op: c.op,
                value: c.op === 'exists' ? true : parseConditionValue(c.value),
              }))]
            : undefined,
        }
      : undefined

    try {
      const res = await fetch(apiUrl('/api/webhooks'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          name: name.trim() || undefined,
          url: url.trim(),
          event_types: eventTypes,
          filter_config,
          enabled: true,
        }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error?.message || 'Failed to create webhook')
      }

      const webhook = await res.json()
      onCreate(webhook)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create webhook')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: theme.overlay,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: theme.bgCard,
          borderRadius: 12,
          padding: 24,
          width: '90%',
          maxWidth: 480,
          maxHeight: '80vh',
          overflow: 'auto',
        }}
        onClick={e => e.stopPropagation()}
      >
        <h3 style={{ margin: '0 0 20px', color: theme.text }}>Create Outbound Webhook</h3>

        <form onSubmit={handleSubmit as any}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, color: theme.text }}>
              Name (optional)
            </label>
            <input
              type="text"
              value={name}
              onChange={e => setName((e.target as HTMLInputElement).value)}
              placeholder="e.g., Slack Notifications"
              style={{
                width: '100%',
                padding: '10px 12px',
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, color: theme.text }}>
              URL *
            </label>
            <input
              type="url"
              value={url}
              onChange={e => setUrl((e.target as HTMLInputElement).value)}
              placeholder="https://example.com/webhook"
              required
              style={{
                width: '100%',
                padding: '10px 12px',
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ marginBottom: 20 }}>
            <label style={{ display: 'block', marginBottom: 8, fontSize: 14, color: theme.text }}>
              Events
            </label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              {availableEvents.map(evt => (
                <label key={evt.id} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={eventTypes.includes(evt.id)}
                    onChange={e => {
                      if ((e.target as HTMLInputElement).checked) {
                        setEventTypes([...eventTypes, evt.id])
                      } else {
                        setEventTypes(eventTypes.filter(t => t !== evt.id))
                      }
                    }}
                    style={{ width: 16, height: 16 }}
                  />
                  <span style={{ fontSize: 14, color: theme.text }}>{evt.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div style={{ marginBottom: 20 }}>
            <label style={{ display: 'block', marginBottom: 8, fontSize: 14, color: theme.text }}>
              Filter by Kind (optional)
            </label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={filterKinds.length === 0}
                  onChange={() => setFilterKinds([])}
                  style={{ width: 16, height: 16 }}
                />
                <span style={{ fontSize: 14, color: theme.text }}>All kinds</span>
              </label>
              {kinds.map(kind => (
                <label key={kind.id} style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={filterKinds.includes(kind.name)}
                    onChange={e => {
                      if ((e.target as HTMLInputElement).checked) {
                        setFilterKinds([...filterKinds, kind.name])
                      } else {
                        setFilterKinds(filterKinds.filter(k => k !== kind.name))
                      }
                    }}
                    style={{ width: 16, height: 16 }}
                  />
                  <span style={{ fontSize: 14, color: theme.text }}>{kind.icon} {kind.name}</span>
                </label>
              ))}
            </div>
            <div style={{ marginTop: 6, fontSize: 12, color: theme.textMuted }}>
              {filterKinds.length === 0 ? 'Triggers for all kinds' : `Triggers for: ${filterKinds.join(', ')}`}
            </div>
          </div>

          {/* Attribute Conditions */}
          <div style={{ marginBottom: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
              <label style={{ fontSize: 14, color: theme.text }}>
                Attribute Filters (optional)
              </label>
              <button
                type="button"
                onClick={addCondition}
                style={{
                  padding: '4px 10px',
                  background: theme.bgHover,
                  color: theme.text,
                  border: `1px solid ${theme.border}`,
                  borderRadius: 4,
                  cursor: 'pointer',
                  fontSize: 12,
                }}
              >
                + Add
              </button>
            </div>
            {conditions.length === 0 ? (
              <div style={{ fontSize: 12, color: theme.textMuted }}>
                No attribute filters. Click "+ Add" to filter by metadata fields.
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {conditions.map((condition, index) => (
                  <div key={index} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <input
                      type="text"
                      placeholder="field"
                      value={condition.field}
                      onChange={e => updateCondition(index, { field: (e.target as HTMLInputElement).value })}
                      style={{
                        flex: 1,
                        padding: '6px 10px',
                        border: `1px solid ${theme.border}`,
                        borderRadius: 4,
                        fontSize: 13,
                        background: theme.bgInput,
                        color: theme.text,
                      }}
                    />
                    <select
                      value={condition.op}
                      onChange={e => updateCondition(index, { op: (e.target as HTMLSelectElement).value })}
                      style={{
                        padding: '6px 8px',
                        border: `1px solid ${theme.border}`,
                        borderRadius: 4,
                        fontSize: 13,
                        background: theme.bgInput,
                        color: theme.text,
                        minWidth: 70,
                      }}
                    >
                      {operators.map(op => (
                        <option key={op.id} value={op.id}>{op.label}</option>
                      ))}
                    </select>
                    {condition.op !== 'exists' && (
                      <input
                        type="text"
                        placeholder="value"
                        value={condition.value}
                        onChange={e => updateCondition(index, { value: (e.target as HTMLInputElement).value })}
                        style={{
                          flex: 1,
                          padding: '6px 10px',
                          border: `1px solid ${theme.border}`,
                          borderRadius: 4,
                          fontSize: 13,
                          background: theme.bgInput,
                          color: theme.text,
                        }}
                      />
                    )}
                    <button
                      type="button"
                      onClick={() => removeCondition(index)}
                      style={{
                        padding: '4px 8px',
                        background: 'transparent',
                        color: theme.error,
                        border: 'none',
                        cursor: 'pointer',
                        fontSize: 16,
                      }}
                    >
                      ×
                    </button>
                  </div>
                ))}
                <div style={{ fontSize: 11, color: theme.textMuted, marginTop: 4 }}>
                  Multiple conditions are AND'd together. Use numbers for numeric comparisons.
                </div>
              </div>
            )}
          </div>

          {error && (
            <div style={{ marginBottom: 16, padding: 12, background: 'rgba(239, 68, 68, 0.1)', borderRadius: 6, color: theme.error, fontSize: 13 }}>
              {error}
            </div>
          )}

          <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '10px 20px',
                background: 'transparent',
                color: theme.textMuted,
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                cursor: 'pointer',
                fontSize: 14,
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !url.trim()}
              style={{
                padding: '10px 20px',
                background: theme.accent,
                color: theme.accentText,
                border: 'none',
                borderRadius: 6,
                cursor: saving ? 'wait' : 'pointer',
                fontSize: 14,
                opacity: saving || !url.trim() ? 0.6 : 1,
              }}
            >
              {saving ? 'Creating...' : 'Create Webhook'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// Create Inbound Webhook Modal
function CreateInboundWebhookModal({
  theme,
  kinds,
  onClose,
  onCreate,
}: {
  theme: Theme
  kinds: Kind[]
  onClose: () => void
  onCreate: (webhook: InboundWebhook) => void
}) {
  const [name, setName] = useState('')
  const [sourceSystem, setSourceSystem] = useState('')
  const [thingType, setThingType] = useState(kinds[0]?.name || 'note')
  const [visibility, setVisibility] = useState('private')
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState<string | null>(null)

  async function handleSubmit(e: Event) {
    e.preventDefault()
    if (!name.trim() || !sourceSystem.trim()) return

    setSaving(true)
    setError(null)

    try {
      const res = await fetch(apiUrl('/api/webhooks/inbound'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          name: name.trim(),
          source_system: sourceSystem.trim().toLowerCase().replace(/\s+/g, '-'),
          default_thing_type: thingType,
          default_visibility: visibility,
          enabled: true,
        }),
      })

      if (!res.ok) {
        const data = await res.json()
        throw new Error(data.error?.message || 'Failed to create webhook')
      }

      const webhook = await res.json()
      onCreate(webhook)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create webhook')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: theme.overlay,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: theme.bgCard,
          borderRadius: 12,
          padding: 24,
          width: '90%',
          maxWidth: 480,
          maxHeight: '80vh',
          overflow: 'auto',
        }}
        onClick={e => e.stopPropagation()}
      >
        <h3 style={{ margin: '0 0 20px', color: theme.text }}>Create Inbound Webhook</h3>

        <form onSubmit={handleSubmit as any}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, color: theme.text }}>
              Name *
            </label>
            <input
              type="text"
              value={name}
              onChange={e => setName((e.target as HTMLInputElement).value)}
              placeholder="e.g., GitHub Importer"
              required
              style={{
                width: '100%',
                padding: '10px 12px',
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
                boxSizing: 'border-box',
              }}
            />
          </div>

          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, color: theme.text }}>
              Source System *
            </label>
            <input
              type="text"
              value={sourceSystem}
              onChange={e => setSourceSystem((e.target as HTMLInputElement).value)}
              placeholder="e.g., github, notion, zapier"
              required
              style={{
                width: '100%',
                padding: '10px 12px',
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
                boxSizing: 'border-box',
              }}
            />
            <p style={{ margin: '6px 0 0', fontSize: 12, color: theme.textMuted }}>
              Identifier for the source of imported data
            </p>
          </div>

          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, color: theme.text }}>
              Default Thing Type
            </label>
            <select
              value={thingType}
              onChange={e => setThingType((e.target as HTMLSelectElement).value)}
              style={{
                width: '100%',
                padding: '10px 12px',
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
              }}
            >
              {kinds.map(kind => (
                <option key={kind.id} value={kind.name}>
                  {kind.icon} {kind.name}
                </option>
              ))}
            </select>
          </div>

          <div style={{ marginBottom: 20 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, color: theme.text }}>
              Default Visibility
            </label>
            <select
              value={visibility}
              onChange={e => setVisibility((e.target as HTMLSelectElement).value)}
              style={{
                width: '100%',
                padding: '10px 12px',
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
              }}
            >
              <option value="private">Private</option>
              <option value="unlisted">Unlisted</option>
              <option value="public">Public</option>
            </select>
          </div>

          {error && (
            <div style={{ marginBottom: 16, padding: 12, background: 'rgba(239, 68, 68, 0.1)', borderRadius: 6, color: theme.error, fontSize: 13 }}>
              {error}
            </div>
          )}

          <div style={{ display: 'flex', gap: 12, justifyContent: 'flex-end' }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '10px 20px',
                background: 'transparent',
                color: theme.textMuted,
                border: `1px solid ${theme.border}`,
                borderRadius: 6,
                cursor: 'pointer',
                fontSize: 14,
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving || !name.trim() || !sourceSystem.trim()}
              style={{
                padding: '10px 20px',
                background: theme.accent,
                color: theme.accentText,
                border: 'none',
                borderRadius: 6,
                cursor: saving ? 'wait' : 'pointer',
                fontSize: 14,
                opacity: saving || !name.trim() || !sourceSystem.trim() ? 0.6 : 1,
              }}
            >
              {saving ? 'Creating...' : 'Create Webhook'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// Settings Page with Tabs
function SettingsPage({
  theme,
  kinds,
  onImportComplete,
  onCreateKind,
  onDeleteKind,
  setEditingKind,
  usedEmojis,
  isMobile,
  defaultKindId,
  onSetDefaultKind,
  initialTab = 'kinds',
}: {
  theme: Theme
  kinds: Kind[]
  onImportComplete: () => void
  onCreateKind: (k: Partial<Kind>) => Promise<Kind | undefined>
  onDeleteKind: (id: string) => void
  setEditingKind: (k: Kind | null) => void
  usedEmojis: string[]
  isMobile: boolean
  defaultKindId: string | null
  onSetDefaultKind: (id: string | null) => void
  initialTab?: 'kinds' | 'data' | 'keys' | 'friends' | 'integrations'
}) {
  const [activeTab, setActiveTab] = useState<'kinds' | 'data' | 'keys' | 'friends' | 'integrations'>(initialTab)

  const tabStyle = (isActive: boolean) => ({
    padding: '8px 16px',
    background: isActive ? theme.accent : 'transparent',
    color: isActive ? theme.accentText : theme.textMuted,
    border: 'none',
    borderRadius: 6,
    cursor: 'pointer',
    fontSize: 14,
    fontWeight: isActive ? 600 : 400,
  })

  return (
    <div>
      {/* Tab Navigation */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 24, background: theme.bgMuted, padding: 4, borderRadius: 8, width: 'fit-content', flexWrap: 'wrap' }}>
        <button onClick={() => setActiveTab('kinds')} style={tabStyle(activeTab === 'kinds')}>
          Kinds
        </button>
        <button onClick={() => setActiveTab('friends')} style={tabStyle(activeTab === 'friends')}>
          Friends
        </button>
        <button onClick={() => setActiveTab('integrations')} style={tabStyle(activeTab === 'integrations')}>
          Integrations
        </button>
        <button onClick={() => setActiveTab('data')} style={tabStyle(activeTab === 'data')}>
          Data
        </button>
        <button onClick={() => setActiveTab('keys')} style={tabStyle(activeTab === 'keys')}>
          API Keys
        </button>
      </div>

      {/* Tab Content */}
      {activeTab === 'kinds' ? (
        <KindsPanel
          kinds={kinds}
          onCreateKind={onCreateKind}
          onDeleteKind={onDeleteKind}
          setEditingKind={setEditingKind}
          usedEmojis={usedEmojis}
          theme={theme}
          defaultKindId={defaultKindId}
          onSetDefaultKind={onSetDefaultKind}
        />
      ) : activeTab === 'friends' ? (
        <FriendsView theme={theme} isMobile={isMobile} />
      ) : activeTab === 'integrations' ? (
        <IntegrationsPanel theme={theme} kinds={kinds} />
      ) : activeTab === 'data' ? (
        <DataExportPanel theme={theme} onImportComplete={onImportComplete} />
      ) : (
        <APIKeysPanel theme={theme} />
      )}
    </div>
  )
}

// Edit Thing Modal
function EditThingModal({
  thing,
  kinds,
  onSave,
  onClose,
  theme,
}: {
  thing: Thing
  kinds: Kind[]
  onSave: (t: Thing) => void
  onClose: () => void
  theme: Theme
}) {
  const [content, setContent] = useState(thing.content)
  const [type, setType] = useState(thing.type)
  const [metadata, setMetadata] = useState<Record<string, unknown>>(thing.metadata || {})
  const [photoCaptions, setPhotoCaptions] = useState<Record<string, string>>(
    thing.photos?.reduce((acc, p) => ({ ...acc, [p.id]: p.caption || '' }), {}) || {}
  )
  const [deletedPhotoIds, setDeletedPhotoIds] = useState<string[]>([])
  const [saving, setSaving] = useState(false)

  const currentKind = kinds.find(k => k.name === type)
  const isGallery = thing.type === 'gallery' && thing.photos && thing.photos.length > 0

  // Filter out deleted photos for display
  const visiblePhotos = thing.photos?.filter(p => !deletedPhotoIds.includes(p.id)) || []

  async function handleSave(e: Event) {
    e.preventDefault()
    setSaving(true)

    try {
      // Delete photos that were marked for deletion
      for (const photoId of deletedPhotoIds) {
        await fetch(apiUrl(`/api/photos/${photoId}`), {
          method: 'DELETE',
          credentials: 'include',
        })
      }

      // Save photo captions if this is a gallery
      if (isGallery && thing.photos) {
        for (const photo of thing.photos) {
          // Skip deleted photos
          if (deletedPhotoIds.includes(photo.id)) continue

          const newCaption = photoCaptions[photo.id] || ''
          if (newCaption !== (photo.caption || '')) {
            await fetch(apiUrl(`/api/photos/${photo.id}`), {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ caption: newCaption }),
              credentials: 'include',
            })
          }
        }
      }

      // Build updated photos array with new captions, excluding deleted photos
      const updatedPhotos = thing.photos
        ?.filter(p => !deletedPhotoIds.includes(p.id))
        .map(p => ({ ...p, caption: photoCaptions[p.id] || p.caption }))

      // Save the thing with updated photos
      onSave({ ...thing, content, type, metadata, photos: updatedPhotos })
    } catch (err) {
      console.error('Failed to save:', err)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: theme.overlay,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: theme.bgCard,
          borderRadius: 12,
          padding: 24,
          width: '100%',
          maxWidth: 500,
          maxHeight: '80vh',
          overflow: 'auto',
        }}
        onClick={e => e.stopPropagation()}
      >
        <h2 style={{ margin: '0 0 20px', fontSize: 20, color: theme.text }}>Edit Thing</h2>
        <form onSubmit={handleSave}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500, color: theme.text }}>Kind</label>
            <select
              value={type}
              onChange={e => {
                setType((e.target as HTMLSelectElement).value)
                setMetadata({})
              }}
              style={{
                width: '100%',
                padding: '10px 14px',
                border: `1px solid ${theme.borderInput}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
              }}
            >
              {kinds.map(kind => (
                <option key={kind.id} value={kind.name}>{kind.icon} {kind.name}</option>
              ))}
            </select>
          </div>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500, color: theme.text }}>Content</label>
            <textarea
              value={content}
              onInput={e => setContent((e.target as HTMLTextAreaElement).value)}
              rows={4}
              style={{
                width: '100%',
                padding: '10px 14px',
                border: `1px solid ${theme.borderInput}`,
                borderRadius: 6,
                fontSize: 14,
                resize: 'vertical',
                boxSizing: 'border-box',
                background: theme.bgInput,
                color: theme.text,
              }}
            />
          </div>

          {/* Kind attributes */}
          {currentKind?.attributes && currentKind.attributes.length > 0 && (
            <div style={{ marginBottom: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <label style={{ fontSize: 14, fontWeight: 500, color: theme.text }}>Attributes</label>
              {currentKind.attributes.map(attr => (
                <AttributeInput
                  key={attr.name}
                  attribute={attr}
                  value={metadata[attr.name]}
                  onChange={val => setMetadata({ ...metadata, [attr.name]: val })}
                  theme={theme}
                />
              ))}
            </div>
          )}

          {/* Photo captions for galleries */}
          {isGallery && visiblePhotos.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', marginBottom: 8, fontSize: 14, fontWeight: 500, color: theme.text }}>
                Photos ({visiblePhotos.length})
              </label>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {visiblePhotos.map((photo, index) => (
                  <div key={photo.id} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <img
                      src={apiUrl(`/api/photos/${photo.id}?size=thumb`)}
                      alt={`Photo ${index + 1}`}
                      style={{
                        width: 60,
                        height: 60,
                        objectFit: 'cover',
                        borderRadius: 4,
                        flexShrink: 0,
                      }}
                    />
                    <input
                      type="text"
                      value={photoCaptions[photo.id] || ''}
                      onChange={e => setPhotoCaptions({ ...photoCaptions, [photo.id]: (e.target as HTMLInputElement).value })}
                      placeholder={`Caption for photo ${index + 1}`}
                      style={{
                        flex: 1,
                        padding: '8px 12px',
                        border: `1px solid ${theme.borderInput}`,
                        borderRadius: 6,
                        fontSize: 13,
                        background: theme.bgInput,
                        color: theme.text,
                      }}
                    />
                    <button
                      type="button"
                      onClick={() => setDeletedPhotoIds([...deletedPhotoIds, photo.id])}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: theme.error,
                        cursor: 'pointer',
                        fontSize: 18,
                        padding: '4px 8px',
                        flexShrink: 0,
                      }}
                      title="Delete photo"
                    >
                      🗑️
                    </button>
                  </div>
                ))}
              </div>
              {deletedPhotoIds.length > 0 && (
                <p style={{ fontSize: 12, color: theme.textMuted, marginTop: 8 }}>
                  {deletedPhotoIds.length} photo(s) will be deleted when you save
                </p>
              )}
            </div>
          )}

          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '10px 20px',
                background: theme.bgHover,
                color: theme.text,
                border: 'none',
                borderRadius: 6,
                cursor: 'pointer',
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              style={{
                padding: '10px 20px',
                background: saving ? theme.textMuted : theme.accent,
                color: theme.accentText,
                border: 'none',
                borderRadius: 6,
                cursor: saving ? 'not-allowed' : 'pointer',
                opacity: saving ? 0.7 : 1,
              }}
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// Edit Kind Modal
function EditKindModal({
  kind,
  onSave,
  onClose,
  usedEmojis,
  theme,
}: {
  kind: Kind
  onSave: (k: Kind) => void
  onClose: () => void
  usedEmojis: string[]
  theme: Theme
}) {
  const [name, setName] = useState(kind.name)
  const [icon, setIcon] = useState(kind.icon || '')
  const [template, setTemplate] = useState<Kind['template']>(kind.template || 'default')
  const [attributes, setAttributes] = useState<Attribute[]>(kind.attributes || [])
  const [commentable, setCommentable] = useState(kind.commentable ?? false)
  const [showExistingComments, setShowExistingComments] = useState(kind.show_existing_comments ?? false)
  const [reactable, setReactable] = useState(kind.reactable ?? true)

  function addAttribute() {
    setAttributes([...attributes, { name: '', type: 'text', required: false, options: '' }])
  }

  function updateAttribute(index: number, field: keyof Attribute, value: string | boolean) {
    const updated = [...attributes]
    updated[index] = { ...updated[index], [field]: value }
    setAttributes(updated)
  }

  function removeAttribute(index: number) {
    setAttributes(attributes.filter((_, i) => i !== index))
  }

  function handleSave(e: Event) {
    e.preventDefault()
    onSave({ ...kind, name, icon, template, attributes, commentable, show_existing_comments: showExistingComments, reactable })
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: theme.overlay,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: theme.bgCard,
          borderRadius: 12,
          padding: 24,
          width: '100%',
          maxWidth: 600,
          maxHeight: '80vh',
          overflow: 'auto',
        }}
        onClick={e => e.stopPropagation()}
      >
        <h2 style={{ margin: '0 0 20px', fontSize: 20, color: theme.text }}>Edit Kind: {kind.name}</h2>
        <form onSubmit={handleSave}>
          <div style={{ display: 'flex', gap: 12, marginBottom: 16, alignItems: 'flex-end' }}>
            <div>
              <label style={{ display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500, color: theme.text }}>Icon</label>
              <EmojiPicker value={icon} onChange={setIcon} usedEmojis={usedEmojis} theme={theme} />
            </div>
            <div style={{ flex: 1 }}>
              <label style={{ display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500, color: theme.text }}>Name</label>
              <input
                type="text"
                value={name}
                onInput={e => setName((e.target as HTMLInputElement).value)}
                style={{ width: '100%', padding: '10px 14px', border: `1px solid ${theme.borderInput}`, borderRadius: 6, boxSizing: 'border-box', background: theme.bgInput, color: theme.text }}
              />
            </div>
          </div>

          {/* Template selector */}
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500, color: theme.text }}>Display Template</label>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {TEMPLATES.map(t => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setTemplate(t.id as Kind['template'])}
                  style={{
                    padding: '8px 14px',
                    border: template === t.id ? `2px solid ${theme.accent}` : `1px solid ${theme.borderInput}`,
                    borderRadius: 6,
                    background: template === t.id ? theme.bgHover : theme.bgInput,
                    color: theme.text,
                    cursor: 'pointer',
                    fontSize: 13,
                  }}
                  title={t.description}
                >
                  {t.name}
                </button>
              ))}
            </div>
            <p style={{ fontSize: 12, color: theme.textMuted, marginTop: 4 }}>
              {TEMPLATES.find(t => t.id === template)?.description}
            </p>
          </div>

          {/* Interaction settings */}
          <div style={{ marginBottom: 20, padding: 16, background: theme.bgSubtle, borderRadius: 8 }}>
            <label style={{ display: 'block', marginBottom: 12, fontSize: 14, fontWeight: 500, color: theme.text }}>Interactions</label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={reactable}
                  onChange={e => setReactable((e.target as HTMLInputElement).checked)}
                  style={{ width: 18, height: 18, cursor: 'pointer' }}
                />
                <span style={{ fontSize: 14, color: theme.text }}>Allow reactions</span>
              </label>
              <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
                <input
                  type="checkbox"
                  checked={commentable}
                  onChange={e => setCommentable((e.target as HTMLInputElement).checked)}
                  style={{ width: 18, height: 18, cursor: 'pointer' }}
                />
                <span style={{ fontSize: 14, color: theme.text }}>Allow replies</span>
              </label>
              {!commentable && (
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', marginLeft: 26 }}>
                  <input
                    type="checkbox"
                    checked={showExistingComments}
                    onChange={e => setShowExistingComments((e.target as HTMLInputElement).checked)}
                    style={{ width: 16, height: 16, cursor: 'pointer' }}
                  />
                  <span style={{ fontSize: 13, color: theme.textMuted }}>Show existing replies (read-only)</span>
                </label>
              )}
            </div>
          </div>

          <div style={{ marginBottom: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <label style={{ fontSize: 14, fontWeight: 500, color: theme.text }}>Attributes</label>
              <button
                type="button"
                onClick={addAttribute}
                style={{
                  padding: '6px 12px',
                  background: theme.bgHover,
                  color: theme.text,
                  border: 'none',
                  borderRadius: 4,
                  cursor: 'pointer',
                  fontSize: 13,
                }}
              >
                + Add Attribute
              </button>
            </div>

            {attributes.length === 0 ? (
              <p style={{ color: theme.textSubtle, fontSize: 14, textAlign: 'center', padding: 20, background: theme.bgSubtle, borderRadius: 8 }}>
                No attributes. Add one to define fields for this kind.
              </p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {attributes.map((attr, i) => (
                  <div key={i} style={{ padding: 12, background: theme.bgSubtle, borderRadius: 8 }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: attr.type === 'select' ? 8 : 0 }}>
                      <input
                        type="text"
                        value={attr.name}
                        placeholder="Field name"
                        onInput={e => updateAttribute(i, 'name', (e.target as HTMLInputElement).value)}
                        style={{ flex: 1, padding: '8px 10px', border: `1px solid ${theme.borderInput}`, borderRadius: 4, fontSize: 13, background: theme.bgInput, color: theme.text }}
                      />
                      <select
                        value={attr.type}
                        onChange={e => updateAttribute(i, 'type', (e.target as HTMLSelectElement).value)}
                        style={{ padding: '8px 10px', border: `1px solid ${theme.borderInput}`, borderRadius: 4, fontSize: 13, background: theme.bgInput, color: theme.text }}
                      >
                        <option value="text">Text</option>
                        <option value="number">Number</option>
                        <option value="date">Date</option>
                        <option value="url">URL</option>
                        <option value="checkbox">Checkbox</option>
                        <option value="select">Select</option>
                      </select>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 13, whiteSpace: 'nowrap', color: theme.text }}>
                        <input
                          type="checkbox"
                          checked={attr.required}
                          onChange={e => updateAttribute(i, 'required', (e.target as HTMLInputElement).checked)}
                        />
                        Required
                      </label>
                      <button
                        type="button"
                        onClick={() => removeAttribute(i)}
                        style={{ padding: '4px 8px', background: 'none', border: 'none', color: theme.errorText, cursor: 'pointer', fontSize: 16 }}
                      >
                        ×
                      </button>
                    </div>

                    {/* Options input for select type */}
                    {attr.type === 'select' && (
                      <div>
                        <input
                          type="text"
                          value={attr.options}
                          placeholder="Options (comma-separated): option1, option2, option3"
                          onInput={e => updateAttribute(i, 'options', (e.target as HTMLInputElement).value)}
                          style={{ width: '100%', padding: '8px 10px', border: `1px solid ${theme.borderInput}`, borderRadius: 4, fontSize: 13, boxSizing: 'border-box', background: theme.bgInput, color: theme.text }}
                        />
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>

          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '10px 20px',
                background: theme.bgHover,
                color: theme.text,
                border: 'none',
                borderRadius: 6,
                cursor: 'pointer',
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              style={{
                padding: '10px 20px',
                background: theme.accent,
                color: theme.accentText,
                border: 'none',
                borderRadius: 6,
                cursor: 'pointer',
              }}
            >
              Save
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// Friends Management View
function FriendsView({
  theme,
  isMobile,
}: {
  theme: Theme
  isMobile: boolean
}) {
  const [following, setFollowing] = useState<Follow[]>([])
  const [followers, setFollowers] = useState<Follow[]>([])
  const [loading, setLoading] = useState(true)
  const [friendUrl, setFriendUrl] = useState('')
  const [adding, setAdding] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [success, setSuccess] = useState<string | null>(null)
  const [mutuals, setMutuals] = useState<Follow[]>([])

  // Convert endpoint to full clickable URL
  function getFullUrl(endpoint: string): string {
    if (endpoint.startsWith('http://') || endpoint.startsWith('https://')) {
      return endpoint
    }
    // For relative paths like /sandbox, use current origin
    return `${window.location.origin}${endpoint}`
  }

  // Fetch following, followers, and mutuals on mount
  useEffect(() => {
    fetchFollows()
  }, [])

  async function fetchFollows() {
    setLoading(true)
    try {
      // Get our user info first
      const authRes = await fetch(apiUrl('/api/auth/status'), { credentials: 'include' })
      const authData = await authRes.json()
      const myUserId = authData.user?.id

      const [followingRes, followersRes] = await Promise.all([
        fetch(apiUrl('/api/follows/following'), { credentials: 'include' }),
        fetch(apiUrl('/api/follows/followers'), { credentials: 'include' }),
      ])

      let followingList: Follow[] = []
      if (followingRes.ok) {
        const data = await followingRes.json()
        followingList = data.data || []
        setFollowing(followingList)
      }
      if (followersRes.ok) {
        const data = await followersRes.json()
        setFollowers(data.data || [])
      }

      // Check mutuals by asking each followed user if they follow us back
      if (myUserId && followingList.length > 0) {
        const mutualChecks = await Promise.all(
          followingList.map(async (follow) => {
            try {
              // Build the URL to check if they follow us
              const checkUrl = follow.remote_endpoint.startsWith('http')
                ? `${follow.remote_endpoint}/api/public/follows/${myUserId}`
                : `${window.location.origin}${follow.remote_endpoint}/api/public/follows/${myUserId}`

              const res = await fetch(checkUrl, { credentials: 'omit' })
              if (res.ok) {
                const data = await res.json()
                return data.data === true ? follow : null
              }
            } catch (e) {
              console.warn(`Failed to check mutual for ${follow.remote_endpoint}:`, e)
            }
            return null
          })
        )
        setMutuals(mutualChecks.filter((f): f is Follow => f !== null))
      }
    } catch (err) {
      console.error('Failed to fetch follows:', err)
    } finally {
      setLoading(false)
    }
  }

  // Normalize friend URL
  function normalizeEndpoint(input: string): string {
    let endpoint = input.trim()

    // If it's just a username (no slashes or protocol), add leading slash
    if (!endpoint.includes('/') && !endpoint.includes(':')) {
      endpoint = '/' + endpoint
    }

    // If it starts with http, it's a full URL - keep as is
    if (endpoint.startsWith('http://') || endpoint.startsWith('https://')) {
      // Remove trailing slash
      return endpoint.replace(/\/$/, '')
    }

    // Otherwise it's a relative path - ensure it starts with /
    if (!endpoint.startsWith('/')) {
      endpoint = '/' + endpoint
    }

    // Remove trailing slash
    return endpoint.replace(/\/$/, '')
  }

  async function addFriend(e: Event) {
    e.preventDefault()
    if (!friendUrl.trim()) return

    setAdding(true)
    setError(null)
    setSuccess(null)

    try {
      // Step 0: Get current user's ID and verify logged in
      const authRes = await fetch(apiUrl('/api/auth/me'), { credentials: 'include' })
      if (!authRes.ok) {
        throw new Error('You must be logged in to follow users')
      }
      const authData = await authRes.json()
      const myUserId = authData.id

      if (!myUserId) {
        throw new Error('You must be logged in to follow users')
      }

      const endpoint = normalizeEndpoint(friendUrl)

      // Prevent following yourself, but allow different paths on same origin
      const currentInstance = window.location.origin + window.location.pathname
      if (endpoint === currentInstance) {
        throw new Error('You cannot follow your own instance')
      }

      // Step 1: Fetch the remote user's public profile to get their user_id
      const profileUrl = endpoint.startsWith('http')
        ? `${endpoint}/api/public/profile`
        : `${endpoint}/api/public/profile`

      const profileRes = await fetch(profileUrl, { credentials: 'omit' })
      if (!profileRes.ok) {
        throw new Error('Could not find user at that address')
      }

      const profile: RemoteProfile = await profileRes.json()

      // Step 2: Create a follow token (must be logged in)
      const tokenRes = await fetch(apiUrl('/api/follows/create-token'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
      })

      if (!tokenRes.ok) {
        throw new Error('Failed to create follow token - are you logged in?')
      }

      const tokenData = await tokenRes.json()
      const followToken = tokenData.data?.follow_token

      if (!followToken) {
        throw new Error('Failed to obtain follow token')
      }

      // Step 3: Send follow request to remote instance with the token
      const notifyUrl = `${endpoint}/api/fed/notify-follow`
      const notifyRes = await fetch(notifyUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'omit',
        body: JSON.stringify({
          follower_user_id: myUserId,
          follower_endpoint: window.location.origin,
          follow_token: followToken,
        }),
      })

      if (!notifyRes.ok) {
        const data = await notifyRes.json()
        throw new Error(data.error || 'Remote instance rejected follow request')
      }

      setSuccess(`Now following ${profile.username || profile.display_name}!`)
      setFriendUrl('')
      fetchFollows()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to add friend')
    } finally {
      setAdding(false)
    }
  }

  async function unfollowUser(userId: string) {
    try {
      const res = await fetch(apiUrl(`/api/follows/${userId}`), {
        method: 'DELETE',
        credentials: 'include',
      })

      if (res.ok) {
        setFollowing(prev => prev.filter(f => f.following_id !== userId))
        setSuccess('Unfollowed successfully')
      }
    } catch (err) {
      setError('Failed to unfollow')
    }
  }

  return (
    <div>
      <h2 style={{ fontSize: 20, margin: '0 0 16px', color: theme.text }}>Friends</h2>

      {/* Mutuals Section - Real Friends */}
      {mutuals.length > 0 && (
        <div style={{
          padding: 20,
          background: theme.bgCard,
          borderRadius: 12,
          border: `1px solid ${theme.accent}`,
          marginBottom: 24,
        }}>
          <h3 style={{ fontSize: 16, margin: '0 0 16px', color: theme.accent }}>
            Mutuals ({mutuals.length})
          </h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {mutuals.map(follow => (
              <div
                key={follow.id}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '12px 16px',
                  background: theme.bgHover,
                  borderRadius: 8,
                }}
              >
                <div>
                  <a
                    href={getFullUrl(follow.remote_endpoint)}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ fontWeight: 500, color: theme.link, textDecoration: 'none' }}
                  >
                    {getFullUrl(follow.remote_endpoint)}
                  </a>
                  <div style={{ fontSize: 12, color: theme.textMuted }}>
                    Friends since {new Date(follow.created_at).toLocaleDateString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Add Friend Section */}
      <div style={{
        padding: 20,
        background: theme.bgCard,
        borderRadius: 12,
        border: `1px solid ${theme.border}`,
        marginBottom: 24,
      }}>
        <h3 style={{ fontSize: 16, margin: '0 0 8px', color: theme.text }}>Add Friend</h3>
        <p style={{ fontSize: 14, color: theme.textMuted, margin: '0 0 16px' }}>
          Enter a username or URL to follow someone.
        </p>

        <form onSubmit={addFriend} style={{ display: 'flex', gap: 8, flexDirection: isMobile ? 'column' : 'row' }}>
          <input
            type="text"
            value={friendUrl}
            onInput={e => setFriendUrl((e.target as HTMLInputElement).value)}
            placeholder="bob or /bob or http://tenant.social/alice"
            style={{
              flex: 1,
              padding: '10px 14px',
              border: `1px solid ${theme.borderInput}`,
              borderRadius: 6,
              fontSize: 14,
              background: theme.bgInput,
              color: theme.text,
            }}
          />
          <button
            type="submit"
            disabled={adding || !friendUrl.trim()}
            style={{
              padding: '10px 20px',
              background: adding ? theme.textDisabled : theme.accent,
              color: adding ? theme.textSubtle : theme.accentText,
              border: 'none',
              borderRadius: 6,
              cursor: adding ? 'not-allowed' : 'pointer',
              fontSize: 14,
              fontWeight: 500,
            }}
          >
            {adding ? 'Adding...' : 'Add Friend'}
          </button>
        </form>

        {error && (
          <p style={{ color: '#ef4444', fontSize: 14, margin: '12px 0 0' }}>{error}</p>
        )}
        {success && (
          <p style={{ color: '#22c55e', fontSize: 14, margin: '12px 0 0' }}>{success}</p>
        )}
      </div>

      {/* Following Section */}
      <div style={{
        padding: 20,
        background: theme.bgCard,
        borderRadius: 12,
        border: `1px solid ${theme.border}`,
        marginBottom: 16,
      }}>
        <h3 style={{ fontSize: 16, margin: '0 0 16px', color: theme.text }}>
          Following ({following.length})
        </h3>

        {loading ? (
          <p style={{ color: theme.textMuted, fontSize: 14 }}>Loading...</p>
        ) : following.length === 0 ? (
          <p style={{ color: theme.textMuted, fontSize: 14 }}>
            You're not following anyone yet. Add a friend above!
          </p>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            {following.map(follow => (
              <div
                key={follow.id}
                style={{
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  padding: '12px 16px',
                  background: theme.bgHover,
                  borderRadius: 8,
                }}
              >
                <div>
                  <a
                    href={getFullUrl(follow.remote_endpoint)}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ fontWeight: 500, color: theme.link, textDecoration: 'none' }}
                  >
                    {getFullUrl(follow.remote_endpoint)}
                  </a>
                  <div style={{ fontSize: 12, color: theme.textMuted }}>
                    Since {new Date(follow.created_at).toLocaleDateString()}
                  </div>
                </div>
                <button
                  onClick={() => unfollowUser(follow.following_id)}
                  style={{
                    padding: '6px 12px',
                    background: 'transparent',
                    color: theme.textMuted,
                    border: `1px solid ${theme.border}`,
                    borderRadius: 6,
                    cursor: 'pointer',
                    fontSize: 13,
                  }}
                >
                  Unfollow
                </button>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Followers Section */}
      <div style={{
        padding: 20,
        background: theme.bgCard,
        borderRadius: 12,
        border: `1px solid ${theme.border}`,
      }}>
        <h3 style={{ fontSize: 16, margin: '0 0 16px', color: theme.text }}>
          Followers ({followers.length})
        </h3>

        {loading ? (
          <p style={{ color: theme.textMuted, fontSize: 14 }}>Loading...</p>
        ) : followers.length === 0 ? (
          <p style={{ color: theme.textMuted, fontSize: 14 }}>
            No one is following you yet.
          </p>
        ) : (() => {
          // Categorize followers as active (confirmed in last 30 days) vs lapsed
          const now = new Date()
          const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000)

          const activeFollowers = followers.filter(f => {
            if (!f.last_confirmed_at) return false
            const confirmedDate = new Date(f.last_confirmed_at)
            return confirmedDate > thirtyDaysAgo
          })

          const lapsedFollowers = followers.filter(f => {
            if (!f.last_confirmed_at) return true
            const confirmedDate = new Date(f.last_confirmed_at)
            return confirmedDate <= thirtyDaysAgo
          })

          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Active Followers */}
              {activeFollowers.length > 0 && (
                <div>
                  <div style={{ fontSize: 13, fontWeight: 500, color: theme.accent, marginBottom: 8 }}>
                    Active ({activeFollowers.length})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {activeFollowers.map(follow => (
                      <div
                        key={follow.id}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          padding: '12px 16px',
                          background: theme.bgHover,
                          borderRadius: 8,
                          borderLeft: `3px solid ${theme.accent}`,
                        }}
                      >
                        <div>
                          <a
                            href={getFullUrl(follow.remote_endpoint)}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{ fontWeight: 500, color: theme.link, textDecoration: 'none' }}
                          >
                            {getFullUrl(follow.remote_endpoint)}
                          </a>
                          <div style={{ fontSize: 12, color: theme.textMuted }}>
                            Following since {new Date(follow.created_at).toLocaleDateString()} · Confirmed {new Date(follow.last_confirmed_at!).toLocaleDateString()}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Lapsed Followers */}
              {lapsedFollowers.length > 0 && (
                <div>
                  <div style={{ fontSize: 13, fontWeight: 500, color: theme.textMuted, marginBottom: 8 }}>
                    Lapsed ({lapsedFollowers.length})
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    {lapsedFollowers.map(follow => (
                      <div
                        key={follow.id}
                        style={{
                          display: 'flex',
                          justifyContent: 'space-between',
                          alignItems: 'center',
                          padding: '12px 16px',
                          background: theme.bgHover,
                          borderRadius: 8,
                          opacity: 0.7,
                        }}
                      >
                        <div>
                          <a
                            href={getFullUrl(follow.remote_endpoint)}
                            target="_blank"
                            rel="noopener noreferrer"
                            style={{ fontWeight: 500, color: theme.link, textDecoration: 'none' }}
                          >
                            {getFullUrl(follow.remote_endpoint)}
                          </a>
                          <div style={{ fontSize: 12, color: theme.textMuted }}>
                            Following since {new Date(follow.created_at).toLocaleDateString()}
                            {follow.last_confirmed_at ? ` · Last confirmed ${new Date(follow.last_confirmed_at).toLocaleDateString()}` : ' · Never confirmed'}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )
        })()}
      </div>
    </div>
  )
}

// ==================== Comments Section ====================

interface CommentTreeNode {
  comment: Comment
  replies: CommentTreeNode[]
}

function buildCommentTree(comments: Comment[]): CommentTreeNode[] {
  const nodeMap = new Map<string, CommentTreeNode>()
  const rootNodes: CommentTreeNode[] = []

  // Create nodes for all comments
  comments.forEach(comment => {
    nodeMap.set(comment.id, { comment, replies: [] })
  })

  // Build tree structure
  comments.forEach(comment => {
    const node = nodeMap.get(comment.id)!
    const parentId = comment.metadata.parent_id
    const rootId = comment.metadata.root_id

    // If parent_id equals root_id, this is a top-level comment
    if (parentId === rootId) {
      rootNodes.push(node)
    } else {
      // This is a reply - find parent and add to its replies
      const parentNode = nodeMap.get(parentId)
      if (parentNode) {
        parentNode.replies.push(node)
      } else {
        // Parent not found (maybe deleted?), treat as root
        rootNodes.push(node)
      }
    }
  })

  // Sort by created_at
  const sortByDate = (a: CommentTreeNode, b: CommentTreeNode) =>
    new Date(a.comment.created_at).getTime() - new Date(b.comment.created_at).getTime()

  rootNodes.sort(sortByDate)
  const sortReplies = (nodes: CommentTreeNode[]) => {
    nodes.sort(sortByDate)
    nodes.forEach(n => sortReplies(n.replies))
  }
  sortReplies(rootNodes)

  return rootNodes
}

function formatTimeAgo(dateString: string): string {
  const date = new Date(dateString)
  const now = new Date()
  const seconds = Math.floor((now.getTime() - date.getTime()) / 1000)

  if (seconds < 60) return 'just now'
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`
  if (seconds < 604800) return `${Math.floor(seconds / 86400)}d ago`
  return date.toLocaleDateString()
}

// Count total descendants in a comment tree
function countDescendants(node: CommentTreeNode): number {
  let count = node.replies.length
  for (const reply of node.replies) {
    count += countDescendants(reply)
  }
  return count
}

function CommentItem({
  node,
  thingId,
  currentUserId,
  thingOwnerId,
  theme,
  onReply,
  onDelete,
  replyingTo,
  setReplyingTo,
  replyContent,
  setReplyContent,
  submittingReply,
  totalComments = 0,
  commentable = true,
}: {
  node: CommentTreeNode
  thingId: string
  currentUserId: string | null
  thingOwnerId: string | null
  theme: Theme
  onReply: (parentId: string, content: string) => Promise<void>
  onDelete: (commentId: string) => Promise<void>
  replyingTo: string | null
  setReplyingTo: (id: string | null) => void
  replyContent: string
  setReplyContent: (content: string) => void
  submittingReply: boolean
  totalComments?: number
  commentable?: boolean
}) {
  const { comment, replies } = node
  const depth = comment.metadata.depth
  const isDeleted = !!comment.deleted_at
  const canDelete = currentUserId && (comment.user_id === currentUserId || thingOwnerId === currentUserId)
  const canReply = commentable && depth < 3 && !isDeleted && currentUserId
  const isReplyingToThis = replyingTo === comment.id
  const totalDescendants = countDescendants(node)

  // Auto-collapse: depth 3+ when thread has >10 total comments
  const shouldAutoCollapse = depth >= 2 && totalComments > 10
  const [expanded, setExpanded] = useState(!shouldAutoCollapse)
  const [deleting, setDeleting] = useState(false)
  const [reactions, setReactions] = useState<ReactionSummary | null>(null)
  const [showHistoryModal, setShowHistoryModal] = useState(false)

  // Fetch reactions for this comment
  useEffect(() => {
    if (isDeleted) return
    fetch(apiUrl(`/api/comments/${comment.id}/reactions`), { credentials: 'include' })
      .then(r => r.ok ? r.json() : null)
      .then(data => data && setReactions(data.data))
      .catch(() => {})
  }, [comment.id, isDeleted])

  // Get display name from author info, fallback to user_id
  const authorName = isDeleted
    ? '[deleted]'
    : comment.author?.display_name || comment.user_id || 'Anonymous'

  const parentAuthorName = comment.parent_author?.display_name || 'Unknown'

  const handleDelete = async () => {
    if (!confirm('Delete this reply?')) return
    setDeleting(true)
    try {
      await onDelete(comment.id)
    } finally {
      setDeleting(false)
    }
  }

  const handleSubmitReply = async () => {
    if (!replyContent.trim()) return
    await onReply(comment.id, replyContent)
  }

  // Collapsed view
  if (!expanded && replies.length > 0) {
    return (
      <div style={{ marginLeft: depth > 0 ? 24 : 0 }}>
        <div
          onClick={() => setExpanded(true)}
          style={{
            padding: '8px 12px',
            margin: '4px 0',
            background: theme.bgCard,
            border: `1px solid ${theme.border}`,
            borderRadius: 6,
            cursor: 'pointer',
            fontSize: 13,
            color: theme.textMuted,
          }}
        >
          <span style={{ marginRight: 8 }}>▶</span>
          <span style={{ fontWeight: 500, color: theme.text }}>{authorName}</span>
          {totalDescendants > 0 && (
            <span> and {totalDescendants} {totalDescendants === 1 ? 'other' : 'others'} ({totalDescendants + 1} {totalDescendants === 0 ? 'reply' : 'replies'})</span>
          )}
        </div>
      </div>
    )
  }

  return (
    <div style={{ marginLeft: depth > 0 ? 24 : 0 }}>
      {/* Reply context blockquote - clickable to collapse */}
      {depth > 0 && comment.parent_content && (
        <div
          onClick={() => replies.length > 0 && setExpanded(false)}
          style={{
            padding: '6px 10px',
            marginBottom: 0,
            background: theme.bgCard,
            borderLeft: `3px solid ${theme.border}`,
            borderTop: `1px solid ${theme.border}`,
            borderRight: `1px solid ${theme.border}`,
            borderTopLeftRadius: 6,
            borderTopRightRadius: 6,
            fontSize: 12,
            color: theme.textMuted,
            cursor: replies.length > 0 ? 'pointer' : 'default',
            display: 'flex',
            alignItems: 'center',
            gap: 6,
          }}
        >
          {replies.length > 0 && <span>▼</span>}
          <span>↳ replying to <strong style={{ color: theme.text }}>{parentAuthorName}</strong>: </span>
          <span style={{ fontStyle: 'italic', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            "{comment.parent_content}"
          </span>
        </div>
      )}

      {/* Comment body */}
      <div
        style={{
          padding: '8px 10px',
          borderLeft: depth > 0 ? `3px solid ${theme.border}` : `1px solid ${theme.border}`,
          borderRight: `1px solid ${theme.border}`,
          borderBottom: `1px solid ${theme.border}`,
          borderTop: depth > 0 && comment.parent_content ? 'none' : `1px solid ${theme.border}`,
          borderRadius: depth > 0 && comment.parent_content ? '0 0 6px 6px' : 6,
          marginBottom: 6,
          background: theme.bg,
        }}
      >
        {/* Header: user + time */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
          <span style={{ fontWeight: 600, color: isDeleted ? theme.textMuted : theme.text, fontSize: 13 }}>
            {authorName}
          </span>
          <span style={{ color: theme.textMuted, fontSize: 12 }}>
            {formatTimeAgo(comment.created_at)}
          </span>
          {totalDescendants > 0 && (
            <span style={{ color: theme.textMuted, fontSize: 11 }}>
              • {totalDescendants} {totalDescendants === 1 ? 'reply' : 'replies'}
            </span>
          )}
        </div>

        {/* Content */}
        <div style={{ color: isDeleted ? theme.textMuted : theme.text, fontSize: 14, lineHeight: 1.5 }}>
          {isDeleted ? <em>[deleted]</em> : comment.content}
        </div>

        {/* Actions */}
        {!isDeleted && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginTop: 6 }}>
            {/* Reactions */}
            {currentUserId && (
              <ReactionBar
                targetId={comment.id}
                targetType="comment"
                reactions={reactions}
                onReactionsChange={setReactions}
                theme={theme}
                compact={true}
              />
            )}
            {/* Show reaction counts even when not logged in */}
            {!currentUserId && reactions && (reactions.counts?.['like'] > 0 || Object.keys(reactions.counts || {}).length > 1) && (
              <span style={{ fontSize: 12, color: theme.textMuted }}>
                {reactions.counts?.['like'] > 0 && `${reactions.counts['like']} like${reactions.counts['like'] !== 1 ? 's' : ''}`}
              </span>
            )}
            {canReply && (
              <button
                onClick={() => setReplyingTo(isReplyingToThis ? null : comment.id)}
                style={{
                  background: 'none',
                  border: 'none',
                  color: theme.textMuted,
                  cursor: 'pointer',
                  fontSize: 12,
                  padding: 0,
                }}
              >
                {isReplyingToThis ? 'Cancel' : 'Reply'}
              </button>
            )}
            {canDelete && (
              <button
                onClick={handleDelete}
                disabled={deleting}
                style={{
                  background: 'none',
                  border: 'none',
                  color: theme.textMuted,
                  cursor: deleting ? 'wait' : 'pointer',
                  fontSize: 12,
                  padding: 0,
                }}
              >
                {deleting ? 'Deleting...' : 'Delete'}
              </button>
            )}
            {/* Edited indicator */}
            {comment.edited_at && (
              <EditedIndicator
                editedAt={comment.edited_at}
                onClick={() => setShowHistoryModal(true)}
                theme={theme}
              />
            )}
          </div>
        )}

        {/* Reply form */}
        {isReplyingToThis && (
          <div style={{ marginTop: 8 }}>
            <textarea
              autoFocus
              value={replyContent}
              onChange={(e) => setReplyContent((e.target as HTMLTextAreaElement).value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter' && !e.shiftKey && replyContent.trim()) {
                  e.preventDefault()
                  handleSubmitReply()
                }
              }}
              placeholder="Write a reply..."
              style={{
                width: '100%',
                minHeight: 40,
                padding: '6px 8px',
                borderRadius: 6,
                border: `1px solid ${theme.border}`,
                background: theme.bgCard,
                color: theme.text,
                fontSize: 13,
                resize: 'vertical',
                fontFamily: 'inherit',
              }}
            />
            <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
              <button
                onClick={handleSubmitReply}
                disabled={submittingReply || !replyContent.trim()}
                style={{
                  padding: '4px 10px',
                  borderRadius: 6,
                  border: 'none',
                  background: theme.accent,
                  color: theme.accentText,
                  fontSize: 12,
                  cursor: submittingReply ? 'wait' : 'pointer',
                  opacity: submittingReply || !replyContent.trim() ? 0.5 : 1,
                }}
              >
                {submittingReply ? 'Posting...' : 'Reply'}
              </button>
              <button
                onClick={() => { setReplyingTo(null); setReplyContent('') }}
                style={{
                  padding: '4px 10px',
                  borderRadius: 6,
                  border: `1px solid ${theme.border}`,
                  background: 'transparent',
                  color: theme.textMuted,
                  fontSize: 12,
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Replies */}
      {replies.length > 0 && expanded && (
        <div>
          {replies.map(reply => (
            <CommentItem
              key={reply.comment.id}
              node={reply}
              thingId={thingId}
              currentUserId={currentUserId}
              thingOwnerId={thingOwnerId}
              theme={theme}
              onReply={onReply}
              onDelete={onDelete}
              replyingTo={replyingTo}
              setReplyingTo={setReplyingTo}
              replyContent={replyContent}
              setReplyContent={setReplyContent}
              submittingReply={submittingReply}
              totalComments={totalComments}
              commentable={commentable}
            />
          ))}
        </div>
      )}

      {/* Edit History Modal */}
      {showHistoryModal && (
        <EditHistoryModal
          targetId={comment.id}
          targetType="comment"
          onClose={() => setShowHistoryModal(false)}
          theme={theme}
        />
      )}
    </div>
  )
}

function CommentsSection({
  thingId,
  thingOwnerId,
  theme,
  commentable = true,
}: {
  thingId: string
  thingOwnerId: string | null
  theme: Theme
  commentable?: boolean
}) {
  const [comments, setComments] = useState<Comment[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [newComment, setNewComment] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [replyingTo, setReplyingTo] = useState<string | null>(null)
  const [replyContent, setReplyContent] = useState('')
  const [submittingReply, setSubmittingReply] = useState(false)
  const [currentUserId, setCurrentUserId] = useState<string | null>(null)
  const [expanded, setExpanded] = useState(true)

  useEffect(() => {
    fetchComments()
    fetchCurrentUser()
  }, [thingId])

  async function fetchCurrentUser() {
    try {
      const res = await fetch(apiUrl('/api/auth/me'), { credentials: 'include' })
      if (res.ok) {
        const data = await res.json()
        setCurrentUserId(data.id || null)
      }
    } catch {
      // Not logged in
    }
  }

  async function fetchComments() {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(apiUrl(`/api/things/${thingId}/comments`), { credentials: 'include' })
      if (res.ok) {
        const data = await res.json()
        // API returns { success: true, data: [...] }
        setComments((data.data || data) as Comment[])
      } else {
        setError('Failed to load comments')
      }
    } catch {
      setError('Failed to load comments')
    } finally {
      setLoading(false)
    }
  }

  async function submitComment(content: string, parentId?: string) {
    const isReply = !!parentId
    if (isReply) {
      setSubmittingReply(true)
    } else {
      setSubmitting(true)
    }

    try {
      const body: Record<string, unknown> = { content }
      if (parentId) {
        body.parentId = parentId
      }

      const res = await fetch(apiUrl(`/api/things/${thingId}/comments`), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
        credentials: 'include',
      })

      if (res.ok) {
        // Refresh comments
        await fetchComments()
        if (isReply) {
          setReplyingTo(null)
          setReplyContent('')
        } else {
          setNewComment('')
        }
      } else {
        const data = await res.json()
        alert(data.error || 'Failed to post comment')
      }
    } catch {
      alert('Failed to post comment')
    } finally {
      if (isReply) {
        setSubmittingReply(false)
      } else {
        setSubmitting(false)
      }
    }
  }

  async function deleteComment(commentId: string) {
    try {
      const res = await fetch(apiUrl(`/api/things/${commentId}`), {
        method: 'DELETE',
        credentials: 'include',
      })
      if (res.ok) {
        await fetchComments()
      } else {
        alert('Failed to delete comment')
      }
    } catch {
      alert('Failed to delete comment')
    }
  }

  const handleReply = async (parentId: string, content: string) => {
    await submitComment(content, parentId)
  }

  const tree = buildCommentTree(comments)
  const commentCount = comments.filter(c => !c.deleted_at).length

  return (
    <div style={{ marginTop: 16, paddingTop: 16, borderTop: `1px solid ${theme.border}` }}>
      {/* Header */}
      <div
        style={{
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          marginBottom: 12,
          cursor: 'pointer',
        }}
        onClick={() => setExpanded(!expanded)}
      >
        <h3 style={{ margin: 0, fontSize: 16, fontWeight: 600, color: theme.text }}>
          Replies {commentCount > 0 && `(${commentCount})`}
        </h3>
        <span style={{ color: theme.textMuted, fontSize: 12 }}>
          {expanded ? '▼' : '▶'}
        </span>
      </div>

      {expanded && (
        <>
          {/* New reply form - only if commentable */}
          {commentable && currentUserId && (
            <div style={{ marginBottom: 12 }}>
              <textarea
                value={newComment}
                onChange={(e) => setNewComment((e.target as HTMLTextAreaElement).value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter' && !e.shiftKey && newComment.trim()) {
                    e.preventDefault()
                    submitComment(newComment)
                  }
                }}
                placeholder="Write a reply..."
                style={{
                  width: '100%',
                  minHeight: 44,
                  padding: '8px 10px',
                  borderRadius: 6,
                  border: `1px solid ${theme.border}`,
                  background: theme.bgCard,
                  color: theme.text,
                  fontSize: 13,
                  resize: 'vertical',
                  fontFamily: 'inherit',
                }}
              />
              <button
                onClick={() => submitComment(newComment)}
                disabled={submitting || !newComment.trim()}
                style={{
                  marginTop: 6,
                  padding: '6px 12px',
                  borderRadius: 6,
                  border: 'none',
                  background: theme.accent,
                  color: theme.accentText,
                  fontSize: 12,
                  cursor: submitting ? 'wait' : 'pointer',
                  opacity: submitting || !newComment.trim() ? 0.5 : 1,
                }}
              >
                {submitting ? 'Posting...' : 'Reply'}
              </button>
            </div>
          )}

          {commentable && !currentUserId && (
            <p style={{ color: theme.textMuted, fontSize: 13, marginBottom: 16 }}>
              <a href={routeHref('/login')} style={{ color: theme.accent }}>Log in</a> to reply.
            </p>
          )}

          {/* Comments list */}
          {loading ? (
            <p style={{ color: theme.textMuted, fontSize: 13 }}>Loading replies...</p>
          ) : error ? (
            <p style={{ color: theme.error, fontSize: 13 }}>{error}</p>
          ) : tree.length === 0 ? (
            commentable ? (
              <p style={{ color: theme.textMuted, fontSize: 13 }}>No replies yet. Be the first!</p>
            ) : null
          ) : (
            <div>
              {tree.map(node => (
                <CommentItem
                  key={node.comment.id}
                  node={node}
                  thingId={thingId}
                  currentUserId={currentUserId}
                  thingOwnerId={thingOwnerId}
                  theme={theme}
                  onReply={handleReply}
                  onDelete={deleteComment}
                  replyingTo={replyingTo}
                  setReplyingTo={setReplyingTo}
                  replyContent={replyContent}
                  setReplyContent={setReplyContent}
                  submittingReply={submittingReply}
                  totalComments={comments.length}
                  commentable={commentable}
                />
              ))}
            </div>
          )}
        </>
      )}
    </div>
  )
}

// Bookmarks View
function BookmarksView({
  theme,
  kinds,
}: {
  theme: Theme
  kinds: Kind[]
}) {
  const [bookmarks, setBookmarks] = useState<Thing[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchBookmarks()
  }, [])

  async function fetchBookmarks() {
    setLoading(true)
    setError(null)
    try {
      const res = await fetch(apiUrl('/api/bookmarks'), { credentials: 'include' })
      if (res.ok) {
        const data = await res.json()
        setBookmarks(data.data || [])
      } else if (res.status === 401) {
        setError('Please log in to view your bookmarks')
      } else {
        setError('Failed to load bookmarks')
      }
    } catch {
      setError('Failed to load bookmarks')
    } finally {
      setLoading(false)
    }
  }

  const getKindForThing = (thing: Thing) => {
    return kinds.find(k => k.name === thing.type)
  }

  if (loading) {
    return (
      <div style={{ padding: 32, textAlign: 'center', color: theme.textMuted }}>
        Loading bookmarks...
      </div>
    )
  }

  if (error) {
    return (
      <div style={{ padding: 32, textAlign: 'center', color: theme.error }}>
        {error}
      </div>
    )
  }

  return (
    <div>
      <h2 style={{ color: theme.text, marginBottom: 16, fontSize: 20 }}>
        Bookmarks
      </h2>
      {bookmarks.length === 0 ? (
        <div style={{
          padding: 32,
          textAlign: 'center',
          color: theme.textMuted,
          background: theme.bgCard,
          borderRadius: 12,
          border: `1px solid ${theme.border}`,
        }}>
          <p style={{ marginBottom: 8 }}>No bookmarks yet</p>
          <p style={{ fontSize: 14 }}>Bookmark things to save them for later</p>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {bookmarks.map(thing => (
            <ThingCard
              key={thing.id}
              thing={thing}
              kind={getKindForThing(thing)}
              theme={theme}
              onEdit={() => {}}
              onDelete={() => {
                // Remove from list when unbookmarked
                setBookmarks(prev => prev.filter(b => b.id !== thing.id))
              }}
              onUpdateThing={(updated) => {
                setBookmarks(prev => prev.map(b => b.id === updated.id ? updated : b))
              }}
            />
          ))}
        </div>
      )}
    </div>
  )
}

// Friends Feed View
function FeedView({
  theme,
  kinds,
}: {
  theme: Theme
  kinds: Kind[]
}) {
  const [feedItems, setFeedItems] = useState<FriendFeedItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    fetchFeed()
  }, [])

  async function fetchFeed() {
    setLoading(true)
    setError(null)
    try {
      // Get current user info for requester params (enables passive follow confirmation)
      const authRes = await fetch(apiUrl('/api/auth/check'), { credentials: 'include' })
      const authData = authRes.ok ? await authRes.json() : null
      const myUserId = authData?.user?.id
      const myEndpoint = window.location.origin

      // Get list of people we're following
      const followingRes = await fetch(apiUrl('/api/follows/following'), { credentials: 'include' })
      if (!followingRes.ok) {
        setError('Failed to load following list')
        return
      }
      const followingData = await followingRes.json()
      const followingList: Follow[] = followingData.data || []

      if (followingList.length === 0) {
        setFeedItems([])
        return
      }

      // Fetch content from each followed user's endpoint
      // Include requester info so they can update last_confirmed_at (passive follow confirmation)
      const allItems: FriendFeedItem[] = []
      await Promise.all(
        followingList.map(async (follow) => {
          try {
            const baseUrl = follow.remote_endpoint.startsWith('http')
              ? follow.remote_endpoint
              : `${window.location.origin}${follow.remote_endpoint}`

            // Build URL with requester info for passive confirmation
            const params = new URLSearchParams({ limit: '20' })
            if (myUserId) {
              params.set('requester_id', myUserId)
              params.set('requester_endpoint', myEndpoint)
            }

            const url = `${baseUrl}/api/fed/things/${follow.following_id}?${params}`
            const res = await fetch(url, { credentials: 'omit' })

            if (res.ok) {
              const data = await res.json()
              const items = data.data || []
              // Add owner info to each item
              items.forEach((item: Thing) => {
                allItems.push({
                  ...item,
                  owner_endpoint: baseUrl,
                  owner_username: follow.following_id,
                })
              })
            }
          } catch (e) {
            console.warn(`Failed to fetch from ${follow.remote_endpoint}:`, e)
          }
        })
      )

      // Sort by created_at descending (newest first)
      allItems.sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
      setFeedItems(allItems)
    } catch (err) {
      console.error('Failed to fetch feed:', err)
      setError('Failed to load feed')
    } finally {
      setLoading(false)
    }
  }

  function getKind(typeName: string): Kind | undefined {
    return kinds.find(k => k.name === typeName)
  }

  function formatDate(dateStr: string): string {
    const date = new Date(dateStr)
    const now = new Date()
    const diffMs = now.getTime() - date.getTime()
    const diffMins = Math.floor(diffMs / 60000)
    const diffHours = Math.floor(diffMs / 3600000)
    const diffDays = Math.floor(diffMs / 86400000)

    if (diffMins < 1) return 'just now'
    if (diffMins < 60) return `${diffMins}m ago`
    if (diffHours < 24) return `${diffHours}h ago`
    if (diffDays < 7) return `${diffDays}d ago`
    return date.toLocaleDateString()
  }

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <h2 style={{ fontSize: 20, margin: 0, color: theme.text }}>Feed</h2>
        <button
          onClick={fetchFeed}
          style={{
            padding: '6px 12px',
            background: theme.bgHover,
            color: theme.textSecondary,
            border: 'none',
            borderRadius: 6,
            cursor: 'pointer',
            fontSize: 13,
          }}
        >
          Refresh
        </button>
      </div>

      {loading ? (
        <div style={{ textAlign: 'center', padding: 40, color: theme.textMuted }}>
          Loading feed...
        </div>
      ) : error ? (
        <div style={{ textAlign: 'center', padding: 40, color: '#ef4444' }}>
          {error}
        </div>
      ) : feedItems.length === 0 ? (
        <div style={{
          textAlign: 'center',
          padding: 40,
          background: theme.bgCard,
          borderRadius: 12,
          border: `1px solid ${theme.border}`,
        }}>
          <p style={{ color: theme.textMuted, fontSize: 16, margin: '0 0 8px' }}>
            Your feed is empty
          </p>
          <p style={{ color: theme.textSubtle, fontSize: 14, margin: 0 }}>
            Follow some friends to see their posts here!
          </p>
          <a
            href={routeHref('/friends')}
            style={{
              display: 'inline-block',
              marginTop: 16,
              padding: '10px 20px',
              background: theme.accent,
              color: theme.accentText,
              borderRadius: 6,
              textDecoration: 'none',
              fontSize: 14,
              fontWeight: 500,
            }}
          >
            Add Friends
          </a>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
          {feedItems.map(item => {
            const kind = getKind(item.type)
            return (
              <div
                key={item.id}
                style={{
                  padding: 16,
                  background: theme.bgCard,
                  borderRadius: 12,
                  border: `1px solid ${theme.border}`,
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 18 }}>{kind?.icon || '📝'}</span>
                    {item.owner_endpoint && (
                      <a
                        href={item.owner_endpoint}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ color: theme.link, textDecoration: 'none', fontWeight: 500 }}
                      >
                        {item.owner_username || item.owner_endpoint}
                      </a>
                    )}
                  </div>
                  <span style={{ fontSize: 12, color: theme.textMuted }}>
                    {formatDate(item.created_at)}
                  </span>
                </div>

                <div style={{ color: theme.text, lineHeight: 1.6 }}>
                  {item.content}
                </div>

                {/* Photos */}
                {item.photos && item.photos.length > 0 && (
                  <div style={{ marginTop: 12, display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                    {item.photos.slice(0, 4).map(photo => (
                      <img
                        key={photo.id}
                        src={item.owner_endpoint
                          ? `${item.owner_endpoint}/api/photos/${photo.id}?size=thumb`
                          : apiUrl(`/api/photos/${photo.id}?size=thumb`)
                        }
                        alt={photo.caption || ''}
                        style={{
                          width: item.photos!.length === 1 ? '100%' : 'calc(50% - 4px)',
                          maxHeight: 200,
                          objectFit: 'cover',
                          borderRadius: 8,
                        }}
                      />
                    ))}
                  </div>
                )}

                <div style={{ marginTop: 8, fontSize: 12, color: theme.textMuted, display: 'flex', gap: 12 }}>
                  <span>{item.visibility === 'public' ? '🌐 Public' : '👥 Friends'}</span>
                  {(item.comment_count ?? 0) > 0 && (
                    <span>💬 {item.comment_count} {item.comment_count === 1 ? 'reply' : 'replies'}</span>
                  )}
                </div>

                {/* Top Replies Preview */}
                {item.top_replies && item.top_replies.length > 0 && (
                  <div style={{
                    marginTop: 12,
                    padding: 12,
                    background: theme.bgSubtle,
                    borderRadius: 8,
                    borderLeft: `3px solid ${theme.border}`,
                  }}>
                    {item.top_replies.map((reply, idx) => (
                      <div key={reply.id} style={{
                        paddingBottom: idx < item.top_replies!.length - 1 ? 8 : 0,
                        marginBottom: idx < item.top_replies!.length - 1 ? 8 : 0,
                        borderBottom: idx < item.top_replies!.length - 1 ? `1px solid ${theme.border}` : 'none',
                      }}>
                        <div style={{ fontSize: 12, color: theme.textMuted, marginBottom: 4 }}>
                          {formatDate(reply.created_at)}
                        </div>
                        <div style={{ fontSize: 14, color: theme.text, lineHeight: 1.5 }}>
                          {reply.content.length > 150 ? reply.content.slice(0, 150) + '...' : reply.content}
                        </div>
                      </div>
                    ))}
                    {(item.comment_count ?? 0) > 2 && (
                      <a
                        href={`${item.owner_endpoint}/post/${item.id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{
                          display: 'block',
                          marginTop: 8,
                          fontSize: 13,
                          color: theme.link,
                          textDecoration: 'none',
                          cursor: 'pointer',
                        }}
                      >
                        View all {item.comment_count} replies →
                      </a>
                    )}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

export default App
