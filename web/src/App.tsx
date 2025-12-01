import { useState, useEffect } from 'preact/hooks'
import { EMOJI_CATEGORIES, ALL_EMOJIS } from './emojis'
import { useTheme, Theme } from './theme.tsx'
import { Markdown } from './Markdown.tsx'

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
  createdAt: string
  updatedAt: string
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
  thingId: string
  caption: string
  orderIndex: number
  contentType: string
  filename: string
  size: number
  createdAt: string
}

interface Thing {
  id: string
  type: string
  content: string
  metadata: Record<string, unknown>
  createdAt: string
  updatedAt: string
  photos?: Photo[]
}

// Default kinds - will be created in DB on first load
const DEFAULT_KINDS: Omit<Kind, 'createdAt' | 'updatedAt'>[] = [
  { id: 'default-note', name: 'note', icon: '📝', template: 'default', attributes: [], isDefault: true },
  { id: 'default-link', name: 'link', icon: '🔗', template: 'link', attributes: [{ name: 'url', type: 'url', required: true, options: '' }], isDefault: true },
  { id: 'default-task', name: 'task', icon: '✅', template: 'checklist', attributes: [{ name: 'done', type: 'checkbox', required: false, options: '' }], isDefault: true },
  { id: 'default-photo', name: 'photo', icon: '📷', template: 'photo', attributes: [], isDefault: true },
  { id: 'default-gallery', name: 'gallery', icon: '🖼️', template: 'photo', attributes: [], isDefault: true },
]

// Simple hash-based routing
function useRoute() {
  const [route, setRoute] = useState(window.location.hash || '#/')

  useEffect(() => {
    const handleHashChange = () => setRoute(window.location.hash || '#/')
    window.addEventListener('hashchange', handleHashChange)
    return () => window.removeEventListener('hashchange', handleHashChange)
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
        <a href="#/about" style={{ color: theme.textMuted, textDecoration: 'none', margin: '0 12px' }}>About</a>
        <a href="#/docs" style={{ color: theme.textMuted, textDecoration: 'none', margin: '0 12px' }}>Docs</a>
        <a href="#/guides" style={{ color: theme.textMuted, textDecoration: 'none', margin: '0 12px' }}>Guides</a>
        <a href="https://github.com/russellromney/tenant.social" target="_blank" rel="noopener noreferrer" style={{ color: theme.textMuted, textDecoration: 'none', margin: '0 12px' }}>GitHub</a>
      </div>
      Made with ❤️ in NYC by <a href="https://russellromney.com" target="_blank" rel="noopener noreferrer" style={{ color: theme.link, textDecoration: 'none' }}>me</a>
    </footer>
  )
}

// Page wrapper for static pages
function PageWrapper({ children, title }: { children: preact.ComponentChildren, title: string }) {
  const { theme } = useTheme()
  return (
    <div style={{ maxWidth: 700, margin: '0 auto', padding: 20, fontFamily: 'system-ui, sans-serif', background: theme.bg, minHeight: '100vh', color: theme.text }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <a href="#/" style={{ textDecoration: 'none', color: theme.text }}>
          <h1 style={{ fontSize: 28, fontWeight: 700, margin: 0 }}>tenant</h1>
        </a>
        <a
          href="#/"
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
      <h2 style={{ fontSize: 24, fontWeight: 600, marginBottom: 24 }}>{title}</h2>
      {children}
      <Footer theme={theme} />
    </div>
  )
}

// About Page
function AboutPage() {
  const { theme } = useTheme()
  return (
    <PageWrapper title="About Tenant">
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
          <li><strong>Multiple views</strong> — See the same data as a feed, table, board, or calendar</li>
          <li><strong>API-first</strong> — Full REST API with granular scopes for integrations</li>
          <li><strong>Version history</strong> — Never lose data, track every change</li>
          <li><strong>Cheap to run</strong> — Single binary, SQLite or Turso, minimal resources</li>
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
    </PageWrapper>
  )
}

// Docs Page
function DocsPage() {
  const { theme } = useTheme()
  return (
    <PageWrapper title="API Documentation">
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

        <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Things</h4>
        <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`GET    /api/things          # List all things
GET    /api/things/:id       # Get a thing
POST   /api/things           # Create a thing
PUT    /api/things/:id       # Update a thing
DELETE /api/things/:id       # Delete a thing
GET    /api/things/search?q= # Search things`}
        </pre>

        <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8, color: theme.text }}>Kinds</h4>
        <pre style={{ background: theme.bgMuted, padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13, color: theme.text }}>
{`GET    /api/kinds           # List all kinds
GET    /api/kinds/:id        # Get a kind
POST   /api/kinds            # Create a kind
PUT    /api/kinds/:id        # Update a kind
DELETE /api/kinds/:id        # Delete a kind`}
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
    </PageWrapper>
  )
}

// Guides Page
function GuidesPage() {
  const { theme } = useTheme()
  return (
    <PageWrapper title="Deployment Guides">
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
    </PageWrapper>
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

  // Sandbox mode - just show enter button
  if (authStatus?.sandboxMode) {
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
          textAlign: 'center',
        }}>
          <h1 style={{ fontSize: 36, fontWeight: 700, margin: '0 0 8px', color: theme.text }}>tenant.social</h1>
          <p style={{ color: theme.textMuted, fontSize: 14, margin: '0 0 20px' }}>
            Your personal social data platform
          </p>
          <p style={{
            background: theme.warning,
            color: theme.warningText,
            padding: '8px 12px',
            borderRadius: 6,
            fontSize: 13,
            margin: '0 0 20px',
          }}>
            This is sandbox mode. Go wild!
          </p>
          <button
            onClick={onAuth}
            style={{
              width: '100%',
              padding: '12px 20px',
              background: theme.accent,
              color: theme.accentText,
              border: 'none',
              borderRadius: 6,
              fontSize: 16,
              fontWeight: 600,
              cursor: 'pointer',
            }}
          >
            Enter Sandbox
          </button>
        </div>
        <Footer theme={theme} />
      </div>
    )
  }

  // Auto-switch to register mode if registration is enabled and no owner
  useEffect(() => {
    if (authStatus?.registrationEnabled && !authStatus?.hasOwner) {
      setMode('register')
    }
  }, [authStatus])

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

  // Show different UI based on whether this is a fresh instance
  const showRegisterOption = authStatus?.registrationEnabled
  const isFreshInstance = !authStatus?.hasOwner

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
          Your personal social data platform
        </p>
        <p style={{ color: theme.textSecondary, fontSize: 14, margin: '0 0 16px', textAlign: 'center', fontWeight: 500 }}>
          {isFreshInstance
            ? 'Claim this instance'
            : (mode === 'register' ? 'Create your account' : 'Sign in to continue')}
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
              : (mode === 'register' ? (isFreshInstance ? 'Claim Instance' : 'Create account') : 'Sign in')}
          </button>
        </form>
        {/* Only show toggle if registration is enabled and there's already an owner */}
        {showRegisterOption && !isFreshInstance && (
          <p style={{ textAlign: 'center', fontSize: 14, color: theme.textMuted, margin: 0 }}>
            {mode === 'register' ? (
              <>Already have an account? <button onClick={() => { setMode('login'); setError('') }} style={{ background: 'none', border: 'none', color: theme.link, cursor: 'pointer', fontSize: 14, padding: 0 }}>Sign in</button></>
            ) : (
              <>Don't have an account? <button onClick={() => { setMode('register'); setError('') }} style={{ background: 'none', border: 'none', color: theme.link, cursor: 'pointer', fontSize: 14, padding: 0 }}>Register</button></>
            )}
          </p>
        )}
        {/* For single-tenant instances with an owner, no registration option */}
        {!showRegisterOption && authStatus?.hasOwner && mode === 'login' && (
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
      const res = await fetch(`/api/things/${postId}`, { credentials: 'include' })
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
      const res = await fetch(`/api/things/${thingId}/backlinks`, { credentials: 'include' })
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
      const res = await fetch(`/api/things/${updated.id}`, {
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
          <a href="#/" style={{ textDecoration: 'none', color: theme.text }}>
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
  const [loading, setLoading] = useState(true)
  const [searchQuery, setSearchQuery] = useState('')
  const [filterKind, setFilterKind] = useState('')
  const [editingThing, setEditingThing] = useState<Thing | null>(null)
  const [editingKind, setEditingKind] = useState<Kind | null>(null)
  const [uploading, setUploading] = useState(false)

  const isKindsPage = route === '#/kinds'
  const isSettingsPage = route === '#/settings' || route === '#/data' || route === '#/keys' // aliases
  const isSubPage = isKindsPage || isSettingsPage

  // Check authentication on mount
  useEffect(() => {
    checkAuth()
  }, [])

  // Restore scroll position when returning to feed from a post
  useEffect(() => {
    const isFeedRoute = route === '#/' || route === ''
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
      const statusRes = await fetch('/api/auth/status', { credentials: 'include' })
      if (statusRes.ok) {
        const status: AuthStatus = await statusRes.json()
        setAuthStatus(status)

        // In sandbox mode, show the welcome screen first (user clicks "Enter Sandbox")
        if (status.authDisabled) {
          setIsAuthenticated(false)
          return
        }
      }

      // Then check if we have a valid session
      const res = await fetch('/api/auth/me', { credentials: 'include' })
      if (res.ok) {
        setIsAuthenticated(true)
      } else {
        setIsAuthenticated(false)
      }
    } catch {
      setIsAuthenticated(false)
    }
  }

  async function handleLogout() {
    try {
      await fetch('/api/auth/logout', {
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
      const res = await fetch('/api/kinds')
      const existingKinds: Kind[] = await res.json()

      // Create default kinds if they don't exist
      for (const defaultKind of DEFAULT_KINDS) {
        const exists = existingKinds.some(k => k.name === defaultKind.name)
        if (!exists) {
          const createRes = await fetch('/api/kinds', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              name: defaultKind.name,
              icon: defaultKind.icon,
              template: defaultKind.template,
              attributes: defaultKind.attributes,
            }),
          })
          const newKind = await createRes.json()
          existingKinds.push(newKind)
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
      const res = await fetch(`/api/things/search?q=${encodeURIComponent(query)}`)
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
      const res = await fetch('/api/things', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          type: newType,
          content: newContent,
          metadata: newMetadata,
        }),
      })
      const thing = await res.json()
      setThings([thing, ...things])
      setNewContent('')
      setNewMetadata({})
    } catch (err) {
      console.error('Failed to create thing:', err)
    }
  }

  async function updateThing(thing: Thing) {
    try {
      const res = await fetch(`/api/things/${thing.id}`, {
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
      await fetch(`/api/things/${id}`, { method: 'DELETE' })
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

      const res = await fetch('/api/upload', {
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
      const res = await fetch('/api/kinds', {
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
      const res = await fetch(`/api/kinds/${kind.id}`, {
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
      await fetch(`/api/kinds/${id}`, { method: 'DELETE' })
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
  if (route === '#/about') {
    return <AboutPage />
  }
  if (route === '#/docs') {
    return <DocsPage />
  }
  if (route === '#/guides') {
    return <GuidesPage />
  }

  // Post detail page - requires authentication
  const postMatch = route.match(/^#\/post\/(.+)$/)
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
        onBack={() => window.location.hash = '#/'}
        onDelete={deleteThing}
        isMobile={isMobile}
      />
    )
  }

  // Show nothing while checking auth
  if (isAuthenticated === null) {
    return null
  }

  // Show auth screen if not authenticated
  if (!isAuthenticated) {
    return <AuthScreen onAuth={() => setIsAuthenticated(true)} authStatus={authStatus} />
  }

  return (
    <div style={{ maxWidth: 700, margin: '0 auto', padding: isMobile ? 12 : 20, fontFamily: 'system-ui, sans-serif', background: theme.bg, minHeight: '100vh', color: theme.text }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: isMobile ? 16 : 24, gap: 8 }}>
        <a href="#/" style={{ textDecoration: 'none', color: theme.text }}>
          <h1 style={{ fontSize: isMobile ? 22 : 28, fontWeight: 700, margin: 0 }}>tenant</h1>
        </a>
        <div style={{ display: 'flex', gap: isMobile ? 4 : 8, alignItems: 'center', flexWrap: 'wrap', justifyContent: 'flex-end' }}>
          <button
            onClick={toggleTheme}
            style={{
              padding: isMobile ? '6px 10px' : '8px 12px',
              background: theme.bgHover,
              color: theme.textMuted,
              border: 'none',
              borderRadius: 6,
              fontSize: 16,
              cursor: 'pointer',
            }}
            title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {isDark ? '☀️' : '🌙'}
          </button>
          {isSubPage ? (
            <a
              href="#/"
              style={{
                padding: isMobile ? '6px 12px' : '8px 16px',
                background: theme.accent,
                color: theme.accentText,
                border: 'none',
                borderRadius: 6,
                fontSize: isMobile ? 13 : 14,
                cursor: 'pointer',
                textDecoration: 'none',
              }}
            >
              ←{isMobile ? '' : ' Back'}
            </a>
          ) : (
            <>
              <a
                href="#/kinds"
                style={{
                  padding: isMobile ? '6px 10px' : '8px 16px',
                  background: theme.bgHover,
                  color: theme.textSecondary,
                  border: 'none',
                  borderRadius: 6,
                  fontSize: isMobile ? 13 : 14,
                  cursor: 'pointer',
                  textDecoration: 'none',
                }}
              >
                {isMobile ? '📋' : 'Kinds'}
              </a>
              <a
                href="#/settings"
                style={{
                  padding: isMobile ? '6px 10px' : '8px 16px',
                  background: theme.bgHover,
                  color: theme.textSecondary,
                  border: 'none',
                  borderRadius: 6,
                  fontSize: isMobile ? 13 : 14,
                  cursor: 'pointer',
                  textDecoration: 'none',
                }}
              >
                ⚙️
              </a>
            </>
          )}
          <button
            onClick={handleLogout}
            style={{
              padding: isMobile ? '6px 10px' : '8px 16px',
              background: theme.bgHover,
              color: theme.textMuted,
              border: 'none',
              borderRadius: 6,
              fontSize: isMobile ? 13 : 14,
              cursor: 'pointer',
            }}
          >
            {isMobile ? '🚪' : 'Logout'}
          </button>
        </div>
      </div>

      {isKindsPage ? (
        <KindsPanel
          kinds={kinds}
          onCreateKind={createKind}
          onDeleteKind={deleteKind}
          setEditingKind={setEditingKind}
          usedEmojis={getUsedEmojis()}
          theme={theme}
        />
      ) : isSettingsPage ? (
        <DataPanel
          theme={theme}
          onImportComplete={() => {
            initializeKinds()
            fetchThings()
          }}
        />
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

              {/* Bottom toolbar - Photo button and Post button */}
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

      <Footer theme={theme} />
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
      window.location.hash = `#/post/${thing.id}`
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
                window.location.hash = `#/post/${linkedId}`
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
          {new Date(thing.createdAt).toLocaleDateString()}
        </span>
        <EditButton /><DeleteButton />
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
          {new Date(thing.createdAt).toLocaleDateString()}
        </span>
        <EditButton /><DeleteButton />
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
              {new Date(thing.createdAt).toLocaleDateString()}
            </div>
          </div>
          <EditButton /><DeleteButton />
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
          <EditButton /><DeleteButton />
        </div>
        <div style={{ padding: 16 }}>
          <Markdown content={thing.content} theme={theme} className="markdown-content" />
          <AttributesDisplay />
          <p style={{ fontSize: 12, color: theme.textSubtle, margin: '12px 0 0' }}>
            {new Date(thing.createdAt).toLocaleString()}
          </p>
        </div>
      </div>
    )
  }

  // PHOTO template - image/video display
  if (template === 'photo') {
    // Handle gallery with multiple photos
    if (thing.photos && thing.photos.length > 0) {
      const [currentPhotoIndex, setCurrentPhotoIndex] = useState(0)
      const [viewerOpen, setViewerOpen] = useState(false)
      const currentPhoto = thing.photos[currentPhotoIndex]
      const isVideo = currentPhoto.contentType?.startsWith('video/')

      // Photo Viewer Modal - keyboard navigation
      useEffect(() => {
        if (!viewerOpen) return
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
      }, [viewerOpen, thing.photos])

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
              alignItems: 'center',
              justifyContent: 'center',
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
              }}
            >
              ×
            </button>

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
                  }}
                >
                  ›
                </button>
              </>
            )}

            {/* Full-size image */}
            <div onClick={(e) => e.stopPropagation()} style={{ maxWidth: '90vw', maxHeight: '90vh', cursor: 'default' }}>
              {isVideo ? (
                <video
                  src={`/api/photos/${currentPhoto.id}?size=full`}
                  controls
                  autoPlay
                  style={{ maxWidth: '90vw', maxHeight: '90vh', objectFit: 'contain' }}
                />
              ) : (
                <img
                  src={`/api/photos/${currentPhoto.id}?size=full`}
                  alt={currentPhoto.caption || 'Photo'}
                  style={{ maxWidth: '90vw', maxHeight: '90vh', objectFit: 'contain' }}
                />
              )}
              {currentPhoto.caption && (
                <p style={{ color: '#fff', textAlign: 'center', marginTop: 12, fontSize: 14 }}>
                  {currentPhoto.caption}
                </p>
              )}
              {thing.photos!.length > 1 && (
                <p style={{ color: 'rgba(255,255,255,0.6)', textAlign: 'center', marginTop: 8, fontSize: 12 }}>
                  {currentPhotoIndex + 1} / {thing.photos!.length}
                </p>
              )}
            </div>
          </div>
        )
      }

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
                src={`/api/photos/${currentPhoto.id}?size=thumb`}
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
                src={`/api/photos/${currentPhoto.id}?size=thumb`}
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
                  {new Date(thing.createdAt).toLocaleString()}
                </p>
              </div>
              <EditButton /><DeleteButton />
            </div>
          </div>
        </div>
      )
    }

    // Handle single photo (metadata.url)
    const url = thing.metadata?.url as string | undefined
    const contentType = thing.metadata?.contentType as string | undefined
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
                {new Date(thing.createdAt).toLocaleString()}
              </p>
            </div>
            <EditButton /><DeleteButton />
          </div>
        </div>
      </div>
    )
  }

  // DEFAULT template - standard card
  return (
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
          <p style={{ fontSize: 12, color: theme.textSubtle, margin: '8px 0 0' }}>
            {new Date(thing.createdAt).toLocaleString()}
          </p>
        </div>
        <EditButton /><DeleteButton />
      </div>
    </div>
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
        const res = await fetch('/api/things', { credentials: 'include' })
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
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 8 }}>
        {linkedThings.map((thing: Thing) => (
          <div
            key={thing.id}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 6,
              padding: '6px 10px',
              background: theme.bgMuted,
              borderRadius: 6,
              fontSize: 13,
              color: theme.text,
            }}
          >
            <span>{thing.content || thing.type}</span>
            <button
              onClick={() => onChange(linkedThingIds.filter(id => id !== thing.id))}
              style={{
                background: 'none',
                border: 'none',
                color: theme.textMuted,
                cursor: 'pointer',
                fontSize: 16,
                padding: 0,
              }}
            >
              ×
            </button>
          </div>
        ))}
      </div>

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
}: {
  kinds: Kind[]
  onCreateKind: (k: Partial<Kind>) => Promise<Kind | undefined>
  onDeleteKind: (id: string) => void
  setEditingKind: (k: Kind | null) => void
  usedEmojis: string[]
  theme: Theme
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
              border: `1px solid ${theme.border}`,
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
                <div style={{ fontWeight: 600, color: theme.text }}>{kind.name}</div>
                <div style={{ fontSize: 12, color: theme.textSubtle }}>
                  {kind.attributes?.length || 0} attributes
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
  keyPrefix: string
  scopes: string[]
  lastUsedAt: string | null
  createdAt: string
}

// Data Management Panel (Import/Export + API Keys)
function DataPanel({
  theme,
  onImportComplete,
}: {
  theme: Theme
  onImportComplete: () => void
}) {
  const [importing, setImporting] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [message, setMessage] = useState<{ type: 'success' | 'error', text: string } | null>(null)

  // API Keys state
  const [apiKeys, setApiKeys] = useState<APIKey[]>([])
  const [availableScopes, setAvailableScopes] = useState<string[]>([])
  const [showCreateKey, setShowCreateKey] = useState(false)
  const [newKeyName, setNewKeyName] = useState('')
  const [newKeyScopes, setNewKeyScopes] = useState<string[]>([])
  const [isAdminKey, setIsAdminKey] = useState(true)
  const [createdKey, setCreatedKey] = useState<string | null>(null)
  const [keyCopied, setKeyCopied] = useState(false)

  // Fetch API keys on mount
  useEffect(() => {
    fetchAPIKeys()
  }, [])

  async function fetchAPIKeys() {
    try {
      const res = await fetch('/api/keys', { credentials: 'include' })
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
      const res = await fetch('/api/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          name: newKeyName,
          scopes: isAdminKey ? [] : newKeyScopes, // empty = all scopes
        }),
      })

      if (!res.ok) throw new Error('Failed to create key')

      const data = await res.json()
      setCreatedKey(data.key) // Show the key once!
      setNewKeyName('')
      setNewKeyScopes([])
      setIsAdminKey(true)
      fetchAPIKeys()
    } catch (err) {
      setMessage({ type: 'error', text: 'Failed to create API key' })
    }
  }

  async function deleteAPIKey(id: string) {
    if (!confirm('Delete this API key? This cannot be undone.')) return

    try {
      await fetch(`/api/keys/${id}`, {
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

  async function handleExport() {
    setExporting(true)
    setMessage(null)
    try {
      const res = await fetch('/api/export', { credentials: 'include' })
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
      const res = await fetch('/api/import', {
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
      <h2 style={{ fontSize: 20, margin: '0 0 16px', color: theme.text }}>Settings</h2>

      <p style={{ color: theme.textSecondary, marginBottom: 24, lineHeight: 1.6 }}>
        Manage your data exports, imports, and API keys.
      </p>

      {/* Export Section */}
      <div style={{
        padding: 20,
        background: theme.bgCard,
        borderRadius: 12,
        border: `1px solid ${theme.border}`,
        marginBottom: 16,
      }}>
        <h3 style={{ fontSize: 16, margin: '0 0 8px', color: theme.text }}>Export Data</h3>
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
        <h3 style={{ fontSize: 16, margin: '0 0 8px', color: theme.text }}>Import Data</h3>
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
          marginBottom: 24,
        }}>
          {message.text}
        </div>
      )}

      {/* API Keys Section */}
      <h2 style={{ fontSize: 20, margin: '32px 0 16px', color: theme.text }}>API Keys</h2>
      <p style={{ color: theme.textSecondary, marginBottom: 24, lineHeight: 1.6 }}>
        Create API keys for programmatic access. Keys can have full admin access or be scoped to specific permissions.
      </p>

      {/* Created Key Display (only shown once!) */}
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
                    {key.keyPrefix}...
                  </code>
                  {' • '}
                  {key.scopes.length === availableScopes.length ? 'Admin' : `${key.scopes.length} scopes`}
                  {key.lastUsedAt && (
                    <>
                      {' • Last used '}
                      {new Date(key.lastUsedAt).toLocaleDateString()}
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
        await fetch(`/api/photos/${photoId}`, {
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
            await fetch(`/api/photos/${photo.id}`, {
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
                      src={`/api/photos/${photo.id}?size=thumb`}
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
    onSave({ ...kind, name, icon, template, attributes })
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

export default App
