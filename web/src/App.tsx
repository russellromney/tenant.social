import { useState, useEffect } from 'preact/hooks'
import { EMOJI_CATEGORIES, ALL_EMOJIS } from './emojis'

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

interface Thing {
  id: string
  type: string
  content: string
  metadata: Record<string, unknown>
  createdAt: string
  updatedAt: string
}

// Default kinds - will be created in DB on first load
const DEFAULT_KINDS: Omit<Kind, 'createdAt' | 'updatedAt'>[] = [
  { id: 'default-note', name: 'note', icon: '📝', template: 'default', attributes: [], isDefault: true },
  { id: 'default-link', name: 'link', icon: '🔗', template: 'link', attributes: [{ name: 'url', type: 'url', required: true, options: '' }], isDefault: true },
  { id: 'default-task', name: 'task', icon: '✅', template: 'checklist', attributes: [{ name: 'done', type: 'checkbox', required: false, options: '' }], isDefault: true },
  { id: 'default-photo', name: 'photo', icon: '📷', template: 'photo', attributes: [], isDefault: true },
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
function Footer() {
  return (
    <footer style={{
      marginTop: 48,
      paddingTop: 24,
      borderTop: '1px solid #eee',
      textAlign: 'center',
      color: '#999',
      fontSize: 14,
    }}>
      <div style={{ marginBottom: 8, color: '#888', fontSize: 13 }}>
        Your personal social data platform
      </div>
      <div style={{ marginBottom: 12 }}>
        <a href="#/about" style={{ color: '#666', textDecoration: 'none', margin: '0 12px' }}>About</a>
        <a href="#/docs" style={{ color: '#666', textDecoration: 'none', margin: '0 12px' }}>Docs</a>
        <a href="#/guides" style={{ color: '#666', textDecoration: 'none', margin: '0 12px' }}>Guides</a>
        <a href="https://github.com/russellromney/tenant.social" target="_blank" rel="noopener noreferrer" style={{ color: '#666', textDecoration: 'none', margin: '0 12px' }}>GitHub</a>
      </div>
      Made with ❤️ in NYC by <a href="https://russellromney.com" target="_blank" rel="noopener noreferrer" style={{ color: '#0ea5e9', textDecoration: 'none' }}>me</a>
    </footer>
  )
}

// Page wrapper for static pages
function PageWrapper({ children, title }: { children: preact.ComponentChildren, title: string }) {
  return (
    <div style={{ maxWidth: 700, margin: '0 auto', padding: 20, fontFamily: 'system-ui, sans-serif' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <a href="#/" style={{ textDecoration: 'none', color: 'inherit' }}>
          <h1 style={{ fontSize: 28, fontWeight: 700, margin: 0 }}>tenant</h1>
        </a>
        <a
          href="#/"
          style={{
            padding: '8px 16px',
            background: '#f5f5f5',
            color: '#333',
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
      <Footer />
    </div>
  )
}

// About Page
function AboutPage() {
  return (
    <PageWrapper title="About Tenant">
      <div style={{ lineHeight: 1.7, color: '#333' }}>
        <p style={{ fontSize: 18, marginBottom: 24 }}>
          <strong>Tenant</strong> is your personal social data platform. Own your data, your way.
        </p>

        <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12 }}>What is Tenant?</h3>
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

        <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12 }}>Philosophy</h3>
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

        <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12 }}>Links</h3>
        <ul style={{ paddingLeft: 24 }}>
          <li><a href="https://github.com/russellromney/tenant.social" style={{ color: '#0ea5e9' }}>GitHub Repository</a></li>
          <li><a href="https://tenant.social" style={{ color: '#0ea5e9' }}>Sandbox (try it out)</a></li>
        </ul>
      </div>
    </PageWrapper>
  )
}

// Docs Page
function DocsPage() {
  return (
    <PageWrapper title="API Documentation">
      <div style={{ lineHeight: 1.7, color: '#333' }}>
        <p style={{ marginBottom: 24 }}>
          Tenant has a full REST API for building integrations. Create an API key in the settings to get started.
        </p>

        <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12 }}>Authentication</h3>
        <p>Use your API key in the Authorization header:</p>
        <pre style={{ background: '#f5f5f5', padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13 }}>
{`curl https://your-tenant.fly.dev/api/things \\
  -H "Authorization: Bearer ts_your_api_key"`}
        </pre>

        <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12 }}>API Scopes</h3>
        <ul style={{ paddingLeft: 24 }}>
          <li><code style={{ background: '#f0f0f0', padding: '2px 6px', borderRadius: 4 }}>things:read</code> — Read things</li>
          <li><code style={{ background: '#f0f0f0', padding: '2px 6px', borderRadius: 4 }}>things:write</code> — Create and update things</li>
          <li><code style={{ background: '#f0f0f0', padding: '2px 6px', borderRadius: 4 }}>things:delete</code> — Delete things</li>
          <li><code style={{ background: '#f0f0f0', padding: '2px 6px', borderRadius: 4 }}>kinds:read</code> — Read kinds</li>
          <li><code style={{ background: '#f0f0f0', padding: '2px 6px', borderRadius: 4 }}>kinds:write</code> — Create and update kinds</li>
          <li><code style={{ background: '#f0f0f0', padding: '2px 6px', borderRadius: 4 }}>kinds:delete</code> — Delete kinds</li>
          <li><code style={{ background: '#f0f0f0', padding: '2px 6px', borderRadius: 4 }}>keys:manage</code> — Manage API keys</li>
        </ul>

        <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12 }}>Endpoints</h3>

        <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8 }}>Things</h4>
        <pre style={{ background: '#f5f5f5', padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13 }}>
{`GET    /api/things          # List all things
GET    /api/things/:id       # Get a thing
POST   /api/things           # Create a thing
PUT    /api/things/:id       # Update a thing
DELETE /api/things/:id       # Delete a thing
GET    /api/things/search?q= # Search things`}
        </pre>

        <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8 }}>Kinds</h4>
        <pre style={{ background: '#f5f5f5', padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13 }}>
{`GET    /api/kinds           # List all kinds
GET    /api/kinds/:id        # Get a kind
POST   /api/kinds            # Create a kind
PUT    /api/kinds/:id        # Update a kind
DELETE /api/kinds/:id        # Delete a kind`}
        </pre>

        <h4 style={{ fontSize: 16, marginTop: 24, marginBottom: 8 }}>Example: Create a Thing</h4>
        <pre style={{ background: '#f5f5f5', padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13 }}>
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
  return (
    <PageWrapper title="Deployment Guides">
      <div style={{ lineHeight: 1.7, color: '#333' }}>
        <p style={{ marginBottom: 24 }}>
          Deploy your own Tenant instance in minutes. Choose your preferred platform:
        </p>

        <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12 }}>🚀 Fly.io (Recommended)</h3>
        <p>Easiest deployment with automatic HTTPS and global edge network.</p>
        <pre style={{ background: '#f5f5f5', padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13 }}>
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

        <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12 }}>🐳 Docker</h3>
        <p>Run anywhere Docker runs.</p>
        <pre style={{ background: '#f5f5f5', padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13 }}>
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

        <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12 }}>💻 Run Locally</h3>
        <p>For development or personal use on your machine.</p>
        <pre style={{ background: '#f5f5f5', padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13 }}>
{`# Clone
git clone https://github.com/russellromney/tenant.social.git
cd tenant.social

# Install frontend dependencies
cd web && npm install && cd ..

# Run (uses local SQLite)
make dev

# Visit http://localhost:3069`}
        </pre>

        <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12 }}>☁️ Turso (Cloud Database)</h3>
        <p>Use Turso for edge-replicated SQLite in the cloud.</p>
        <pre style={{ background: '#f5f5f5', padding: 16, borderRadius: 8, overflow: 'auto', fontSize: 13 }}>
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

        <h3 style={{ fontSize: 18, marginTop: 32, marginBottom: 12 }}>Environment Variables</h3>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 14 }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #ddd' }}>
              <th style={{ textAlign: 'left', padding: '8px 0' }}>Variable</th>
              <th style={{ textAlign: 'left', padding: '8px 0' }}>Description</th>
            </tr>
          </thead>
          <tbody>
            <tr style={{ borderBottom: '1px solid #eee' }}>
              <td style={{ padding: '8px 0' }}><code>PORT</code></td>
              <td style={{ padding: '8px 0' }}>Server port (default: 8069)</td>
            </tr>
            <tr style={{ borderBottom: '1px solid #eee' }}>
              <td style={{ padding: '8px 0' }}><code>PRODUCTION</code></td>
              <td style={{ padding: '8px 0' }}>Set to "true" for production mode</td>
            </tr>
            <tr style={{ borderBottom: '1px solid #eee' }}>
              <td style={{ padding: '8px 0' }}><code>DB_BACKEND</code></td>
              <td style={{ padding: '8px 0' }}>"sqlite" or "turso"</td>
            </tr>
            <tr style={{ borderBottom: '1px solid #eee' }}>
              <td style={{ padding: '8px 0' }}><code>SQLITE_PATH</code></td>
              <td style={{ padding: '8px 0' }}>Path to SQLite database file</td>
            </tr>
            <tr style={{ borderBottom: '1px solid #eee' }}>
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
        background: '#fafafa',
        flexDirection: 'column',
      }}>
        <div style={{
          background: 'white',
          padding: 32,
          borderRadius: 12,
          boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
          width: '100%',
          maxWidth: 380,
          textAlign: 'center',
        }}>
          <h1 style={{ fontSize: 36, fontWeight: 700, margin: '0 0 8px' }}>tenant.social</h1>
          <p style={{ color: '#666', fontSize: 14, margin: '0 0 20px' }}>
            Your personal social data platform
          </p>
          <p style={{
            background: '#fef3c7',
            color: '#92400e',
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
              background: '#1a1a1a',
              color: 'white',
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
        <Footer />
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
      background: '#fafafa',
      flexDirection: 'column',
    }}>
      <div style={{
        background: 'white',
        padding: 32,
        borderRadius: 12,
        boxShadow: '0 4px 12px rgba(0,0,0,0.1)',
        width: '100%',
        maxWidth: 380,
      }}>
        <h1 style={{ fontSize: 36, fontWeight: 700, margin: '0 0 8px', textAlign: 'center' }}>tenant.social</h1>
        <p style={{ color: '#666', fontSize: 14, margin: '0 0 20px', textAlign: 'center' }}>
          Your personal social data platform
        </p>
        <p style={{ color: '#333', fontSize: 14, margin: '0 0 16px', textAlign: 'center', fontWeight: 500 }}>
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
              border: '1px solid #ddd',
              borderRadius: 6,
              fontSize: 16,
              boxSizing: 'border-box',
              marginBottom: 12,
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
                border: '1px solid #ddd',
                borderRadius: 6,
                fontSize: 16,
                boxSizing: 'border-box',
                marginBottom: 12,
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
              border: error ? '1px solid #e44' : '1px solid #ddd',
              borderRadius: 6,
              fontSize: 16,
              boxSizing: 'border-box',
              marginBottom: 12,
            }}
          />
          {error && (
            <p style={{ color: '#e44', fontSize: 13, margin: '0 0 12px' }}>{error}</p>
          )}
          <button
            type="submit"
            disabled={!isValid || loading}
            style={{
              width: '100%',
              padding: '12px 20px',
              background: isValid && !loading ? '#1a1a1a' : '#ccc',
              color: 'white',
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
          <p style={{ textAlign: 'center', fontSize: 14, color: '#666', margin: 0 }}>
            {mode === 'register' ? (
              <>Already have an account? <button onClick={() => { setMode('login'); setError('') }} style={{ background: 'none', border: 'none', color: '#0ea5e9', cursor: 'pointer', fontSize: 14, padding: 0 }}>Sign in</button></>
            ) : (
              <>Don't have an account? <button onClick={() => { setMode('register'); setError('') }} style={{ background: 'none', border: 'none', color: '#0ea5e9', cursor: 'pointer', fontSize: 14, padding: 0 }}>Register</button></>
            )}
          </p>
        )}
        {/* For single-tenant instances with an owner, no registration option */}
        {!showRegisterOption && authStatus?.hasOwner && mode === 'login' && (
          <p style={{ textAlign: 'center', fontSize: 12, color: '#999', margin: 0 }}>
            This is a private instance
          </p>
        )}
      </div>
      <Footer />
    </div>
  )
}

function App() {
  const route = useRoute()
  const isMobile = useIsMobile()
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

  // Check authentication on mount
  useEffect(() => {
    checkAuth()
  }, [])

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

  async function handlePhotoUpload(e: Event) {
    const input = e.target as HTMLInputElement
    const files = input.files
    if (!files || files.length === 0) return

    setUploading(true)
    for (let i = 0; i < files.length; i++) {
      const file = files[i]
      if (file.type.startsWith('image/') || file.type.startsWith('video/')) {
        try {
          const formData = new FormData()
          formData.append('file', file)

          const res = await fetch('/api/upload', {
            method: 'POST',
            body: formData,
            credentials: 'include',
          })

          if (res.ok) {
            const thing = await res.json()
            setThings(prev => [thing, ...prev])
          }
        } catch (err) {
          console.error('Failed to upload photo:', err)
        }
      }
    }
    setUploading(false)
    input.value = '' // Reset input
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

  // Show nothing while checking auth
  if (isAuthenticated === null) {
    return null
  }

  // Show auth screen if not authenticated
  if (!isAuthenticated) {
    return <AuthScreen onAuth={() => setIsAuthenticated(true)} authStatus={authStatus} />
  }

  return (
    <div style={{ maxWidth: 700, margin: '0 auto', padding: 20, fontFamily: 'system-ui, sans-serif' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 24 }}>
        <a href="#/" style={{ textDecoration: 'none', color: 'inherit' }}>
          <h1 style={{ fontSize: 28, fontWeight: 700, margin: 0 }}>tenant</h1>
        </a>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <a
            href={isKindsPage ? '#/' : '#/kinds'}
            style={{
              padding: '8px 16px',
              background: isKindsPage ? '#1a1a1a' : '#f5f5f5',
              color: isKindsPage ? 'white' : '#333',
              border: 'none',
              borderRadius: 6,
              fontSize: 14,
              cursor: 'pointer',
              textDecoration: 'none',
            }}
          >
            {isKindsPage ? '← Back' : 'Manage Kinds'}
          </a>
          <button
            onClick={handleLogout}
            style={{
              padding: '8px 16px',
              background: '#f5f5f5',
              color: '#666',
              border: 'none',
              borderRadius: 6,
              fontSize: 14,
              cursor: 'pointer',
            }}
          >
            Logout
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
        />
      ) : (
        <>
          {/* Search & Filter */}
          <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
            <input
              type="text"
              value={searchQuery}
              onInput={e => setSearchQuery((e.target as HTMLInputElement).value)}
              placeholder="Search things..."
              style={{
                flex: 1,
                padding: '10px 14px',
                border: '1px solid #ddd',
                borderRadius: 6,
                fontSize: 14,
              }}
            />
            <select
              value={filterKind}
              onChange={e => setFilterKind((e.target as HTMLSelectElement).value)}
              style={{
                padding: '10px 14px',
                border: '1px solid #ddd',
                borderRadius: 6,
                fontSize: 14,
                background: 'white',
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
                background: 'white',
                border: '2px solid #e5e5e5',
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
                  borderBottom: '1px solid #f0f0f0',
                }}
              >
                <KindSelector
                  kinds={getSortedKindsByFrequency()}
                  selectedType={newType}
                  onSelectType={setNewType}
                  visibleCount={isMobile ? 2 : 4}
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
                  }}
                />

                {/* Kind-specific attributes */}
                {currentKind?.attributes && currentKind.attributes.length > 0 && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 12, paddingTop: 12, borderTop: '1px solid #f0f0f0' }}>
                    {currentKind.attributes.map(attr => (
                      <AttributeInput
                        key={attr.name}
                        attribute={attr}
                        value={newMetadata[attr.name]}
                        onChange={val => setNewMetadata({ ...newMetadata, [attr.name]: val })}
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
                  background: '#fafafa',
                  borderTop: '1px solid #f0f0f0',
                }}
              >
                <label
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
                    color: '#666',
                  }}
                >
                  <input
                    type="file"
                    accept="image/*,video/*"
                    multiple
                    onChange={handlePhotoUpload}
                    style={{ display: 'none' }}
                    disabled={uploading}
                  />
                  <span style={{ fontSize: 18 }}>📷</span>
                  <span>{uploading ? 'Uploading...' : 'Photo'}</span>
                </label>
                <button
                  type="submit"
                  disabled={!newContent.trim()}
                  style={{
                    padding: '8px 20px',
                    background: newContent.trim() ? '#1a1a1a' : '#ccc',
                    color: 'white',
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
            <p style={{ color: '#666' }}>
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
        />
      )}

      {/* Edit Kind Modal */}
      {editingKind && (
        <EditKindModal
          kind={editingKind}
          onSave={updateKind}
          onClose={() => setEditingKind(null)}
          usedEmojis={getUsedEmojis().filter(e => e !== editingKind.icon)}
        />
      )}

      <Footer />
    </div>
  )
}

// Responsive Kind Selector Component
function KindSelector({
  kinds,
  selectedType,
  onSelectType,
  visibleCount,
}: {
  kinds: Kind[]
  selectedType: string
  onSelectType: (type: string) => void
  visibleCount: number
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
              background: isSelected ? '#1a1a1a' : '#f0f0f0',
              color: isSelected ? 'white' : '#333',
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
            background: selectedInHidden ? '#1a1a1a' : '#f0f0f0',
            color: selectedInHidden ? 'white' : '#666',
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
}: {
  thing: Thing
  kind: Kind | undefined
  onEdit: () => void
  onDelete: () => void
  onUpdateThing: (thing: Thing) => void
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
        color: '#ccc',
        cursor: 'pointer',
        fontSize: 18,
        padding: '4px 8px',
        flexShrink: 0,
      }}
      onMouseEnter={e => (e.currentTarget.style.color = '#f44')}
      onMouseLeave={e => (e.currentTarget.style.color = '#ccc')}
    >
      ×
    </button>
  )

  // Attributes display (shared across templates)
  const AttributesDisplay = ({ compact = false }: { compact?: boolean }) => {
    if (!kind?.attributes || Object.keys(thing.metadata || {}).length === 0) return null
    return (
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: compact ? 4 : 8, marginTop: compact ? 4 : 8 }}>
        {kind.attributes.map(attr => {
          const val = thing.metadata?.[attr.name]
          if (val === undefined || val === null || val === '') return null
          return (
            <span
              key={attr.name}
              style={{
                fontSize: compact ? 11 : 12,
                padding: compact ? '1px 6px' : '2px 8px',
                background: '#f0f0f0',
                borderRadius: 4,
                color: '#666',
              }}
            >
              {attr.type === 'checkbox' ? (val ? '✓ ' : '○ ') : ''}
              {attr.type === 'url' ? (
                <a
                  href={String(val)}
                  target="_blank"
                  onClick={e => e.stopPropagation()}
                  style={{ color: '#0ea5e9', textDecoration: 'none' }}
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

  // COMPACT template - minimal one-line display
  if (template === 'compact') {
    return (
      <div
        onClick={onEdit}
        style={{
          display: 'flex',
          alignItems: 'center',
          gap: 10,
          padding: '10px 14px',
          background: 'white',
          borderRadius: 6,
          border: '1px solid #eee',
          cursor: 'pointer',
          transition: 'background 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.background = '#fafafa')}
        onMouseLeave={e => (e.currentTarget.style.background = 'white')}
      >
        <span style={{ fontSize: 16 }}>{icon}</span>
        <span style={{ flex: 1, fontSize: 14, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
          {thing.content}
        </span>
        <span style={{ fontSize: 11, color: '#999', flexShrink: 0 }}>
          {new Date(thing.createdAt).toLocaleDateString()}
        </span>
        <DeleteButton />
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
          background: 'white',
          borderRadius: 8,
          border: '1px solid #eee',
          cursor: 'pointer',
          transition: 'background 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.background = '#fafafa')}
        onMouseLeave={e => (e.currentTarget.style.background = 'white')}
      >
        <input
          type="checkbox"
          checked={isDone}
          onChange={(e) => {
            e.stopPropagation()
            onUpdateThing({ ...thing, metadata: { ...thing.metadata, done: !isDone } })
          }}
          style={{ width: 18, height: 18, marginTop: 2, cursor: 'pointer', accentColor: '#1a1a1a' }}
        />
        <div style={{ flex: 1 }} onClick={onEdit}>
          <span
            style={{
              fontSize: 15,
              textDecoration: isDone ? 'line-through' : 'none',
              color: isDone ? '#999' : '#1a1a1a',
            }}
          >
            {thing.content}
          </span>
          <AttributesDisplay compact />
        </div>
        <span style={{ fontSize: 11, color: '#999', flexShrink: 0 }}>
          {new Date(thing.createdAt).toLocaleDateString()}
        </span>
        <DeleteButton />
      </div>
    )
  }

  // LINK template - URL-focused
  if (template === 'link') {
    const url = thing.metadata?.url as string | undefined
    return (
      <div
        onClick={onEdit}
        style={{
          padding: 14,
          background: 'white',
          borderRadius: 8,
          border: '1px solid #eee',
          borderLeft: '4px solid #1a1a1a',
          cursor: 'pointer',
          transition: 'box-shadow 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.boxShadow = '0 2px 8px rgba(0,0,0,0.08)')}
        onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
          <div style={{ flex: 1 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
              <span style={{ fontSize: 16 }}>{icon}</span>
              <span style={{ fontSize: 15, fontWeight: 500 }}>{thing.content}</span>
            </div>
            {url && (
              <a
                href={url}
                target="_blank"
                rel="noopener noreferrer"
                onClick={e => e.stopPropagation()}
                style={{
                  fontSize: 13,
                  color: '#0ea5e9',
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
            <div style={{ fontSize: 11, color: '#999', marginTop: 6 }}>
              {new Date(thing.createdAt).toLocaleDateString()}
            </div>
          </div>
          <DeleteButton />
        </div>
      </div>
    )
  }

  // CARD template - rich card with prominent content
  if (template === 'card') {
    return (
      <div
        onClick={onEdit}
        style={{
          background: 'white',
          borderRadius: 12,
          border: '1px solid #eee',
          overflow: 'hidden',
          cursor: 'pointer',
          transition: 'box-shadow 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.1)')}
        onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
      >
        <div style={{ background: '#f5f5f5', padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 20 }}>{icon}</span>
          <span style={{ fontSize: 12, fontWeight: 600, color: '#666', textTransform: 'uppercase', letterSpacing: 0.5 }}>
            {thing.type}
          </span>
          <div style={{ flex: 1 }} />
          <DeleteButton />
        </div>
        <div style={{ padding: 16 }}>
          <p style={{ fontSize: 17, margin: 0, lineHeight: 1.5, fontWeight: 500 }}>{thing.content}</p>
          <AttributesDisplay />
          <p style={{ fontSize: 12, color: '#999', margin: '12px 0 0' }}>
            {new Date(thing.createdAt).toLocaleString()}
          </p>
        </div>
      </div>
    )
  }

  // PHOTO template - image/video display
  if (template === 'photo') {
    const url = thing.metadata?.url as string | undefined
    const contentType = thing.metadata?.contentType as string | undefined
    const isVideo = contentType?.startsWith('video/')

    return (
      <div
        style={{
          background: 'white',
          borderRadius: 12,
          border: '1px solid #eee',
          overflow: 'hidden',
          transition: 'box-shadow 0.15s',
        }}
        onMouseEnter={e => (e.currentTarget.style.boxShadow = '0 4px 12px rgba(0,0,0,0.1)')}
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
                background: '#f5f5f5',
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
                <p
                  style={{ fontSize: 14, margin: '0 0 8px', lineHeight: 1.4, cursor: 'pointer' }}
                  onClick={onEdit}
                >
                  {thing.content}
                </p>
              )}
              <p style={{ fontSize: 11, color: '#999', margin: 0 }}>
                {new Date(thing.createdAt).toLocaleString()}
              </p>
            </div>
            <DeleteButton />
          </div>
        </div>
      </div>
    )
  }

  // DEFAULT template - standard card
  return (
    <div
      onClick={onEdit}
      style={{
        padding: 16,
        background: 'white',
        borderRadius: 8,
        border: '1px solid #eee',
        cursor: 'pointer',
        transition: 'box-shadow 0.15s',
      }}
      onMouseEnter={e => (e.currentTarget.style.boxShadow = '0 2px 8px rgba(0,0,0,0.08)')}
      onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
    >
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start' }}>
        <div style={{ flex: 1 }}>
          <span
            style={{
              display: 'inline-block',
              padding: '3px 10px',
              background: '#f0f0f0',
              color: '#666',
              borderRadius: 4,
              fontSize: 12,
              fontWeight: 500,
              marginBottom: 8,
            }}
          >
            {icon} {thing.type}
          </span>
          <p style={{ fontSize: 16, margin: '8px 0', lineHeight: 1.5 }}>{thing.content}</p>
          <AttributesDisplay />
          <p style={{ fontSize: 12, color: '#999', margin: '8px 0 0' }}>
            {new Date(thing.createdAt).toLocaleString()}
          </p>
        </div>
        <DeleteButton />
      </div>
    </div>
  )
}

// Attribute Input Component
function AttributeInput({
  attribute,
  value,
  onChange,
}: {
  attribute: Attribute
  value: unknown
  onChange: (val: unknown) => void
}) {
  const labelStyle = { fontSize: 13, color: '#666', marginBottom: 4, display: 'block' }
  const inputStyle = {
    width: '100%',
    padding: '8px 12px',
    border: '1px solid #ddd',
    borderRadius: 6,
    fontSize: 14,
    boxSizing: 'border-box' as const,
    background: 'white',
  }

  switch (attribute.type) {
    case 'checkbox':
      return (
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14 }}>
          <input
            type="checkbox"
            checked={Boolean(value)}
            onChange={e => onChange((e.target as HTMLInputElement).checked)}
          />
          {attribute.name} {attribute.required && <span style={{ color: '#c44' }}>*</span>}
        </label>
      )
    case 'select':
      const options = attribute.options.split(',').map(o => o.trim()).filter(Boolean)
      return (
        <div>
          <label style={labelStyle}>{attribute.name} {attribute.required && <span style={{ color: '#c44' }}>*</span>}</label>
          <select
            value={String(value || '')}
            onChange={e => onChange((e.target as HTMLSelectElement).value)}
            style={{ ...inputStyle, background: 'white' }}
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
          <label style={labelStyle}>{attribute.name} {attribute.required && <span style={{ color: '#c44' }}>*</span>}</label>
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
          <label style={labelStyle}>{attribute.name} {attribute.required && <span style={{ color: '#c44' }}>*</span>}</label>
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
          <label style={labelStyle}>{attribute.name} {attribute.required && <span style={{ color: '#c44' }}>*</span>}</label>
          <input
            type="url"
            value={String(value || '')}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            placeholder="https://..."
            style={inputStyle}
          />
        </div>
      )
    default:
      return (
        <div>
          <label style={labelStyle}>{attribute.name} {attribute.required && <span style={{ color: '#c44' }}>*</span>}</label>
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
}: {
  value: string
  onChange: (emoji: string) => void
  usedEmojis: string[]
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
          border: '1px solid #ddd',
          borderRadius: 6,
          background: 'white',
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
            background: 'white',
            border: '1px solid #ddd',
            borderRadius: 8,
            boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
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
              borderBottom: '1px solid #eee',
              borderRadius: '8px 8px 0 0',
              fontSize: 14,
              boxSizing: 'border-box',
              outline: 'none',
              flexShrink: 0,
            }}
          />

          {/* Category tabs */}
          {!search.trim() && (
            <div style={{ display: 'flex', borderBottom: '1px solid #eee', padding: '4px 4px 0', gap: 2 }}>
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
                    background: selectedCategory === i ? '#f0f0f0' : 'transparent',
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
                    background: value === emoji ? '#e0e7ff' : 'transparent',
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
              <div style={{ gridColumn: '1 / -1', padding: 12, textAlign: 'center', color: '#999', fontSize: 13 }}>
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
}: {
  kinds: Kind[]
  onCreateKind: (k: Partial<Kind>) => Promise<Kind | undefined>
  onDeleteKind: (id: string) => void
  setEditingKind: (k: Kind | null) => void
  usedEmojis: string[]
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
      <h2 style={{ fontSize: 20, margin: '0 0 16px' }}>Kinds</h2>

      {/* Create new kind */}
      <form onSubmit={handleCreate} style={{ marginBottom: 24 }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'flex-end' }}>
          <div>
            <label style={{ fontSize: 12, color: '#666', display: 'block', marginBottom: 4 }}>Icon</label>
            <EmojiPicker value={newIcon} onChange={setNewIcon} usedEmojis={usedEmojis} />
          </div>
          <div style={{ flex: 1 }}>
            <label style={{ fontSize: 12, color: '#666', display: 'block', marginBottom: 4 }}>Name</label>
            <input
              type="text"
              value={newName}
              onInput={e => setNewName((e.target as HTMLInputElement).value)}
              placeholder="New kind name..."
              style={{ width: '100%', padding: '10px 14px', border: '1px solid #ddd', borderRadius: 6, boxSizing: 'border-box' }}
            />
          </div>
          <button
            type="submit"
            disabled={!newName.trim() || !newIcon}
            style={{
              padding: '10px 20px',
              background: newName.trim() && newIcon ? '#1a1a1a' : '#ccc',
              color: 'white',
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
              background: 'white',
              borderRadius: 8,
              border: '1px solid #eee',
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
                  background: '#f0f0f0',
                  borderRadius: 8,
                  fontSize: 18,
                }}
              >
                {kind.icon || '•'}
              </span>
              <div>
                <div style={{ fontWeight: 600 }}>{kind.name}</div>
                <div style={{ fontSize: 12, color: '#999' }}>
                  {kind.attributes?.length || 0} attributes
                </div>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                onClick={() => setEditingKind(kind)}
                style={{
                  padding: '6px 12px',
                  background: '#f5f5f5',
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
                  background: '#fee',
                  color: '#c44',
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
          <p style={{ color: '#666', textAlign: 'center', padding: 20 }}>
            No kinds yet. Create one above!
          </p>
        )}
      </div>
    </div>
  )
}

// Edit Thing Modal
function EditThingModal({
  thing,
  kinds,
  onSave,
  onClose,
}: {
  thing: Thing
  kinds: Kind[]
  onSave: (t: Thing) => void
  onClose: () => void
}) {
  const [content, setContent] = useState(thing.content)
  const [type, setType] = useState(thing.type)
  const [metadata, setMetadata] = useState<Record<string, unknown>>(thing.metadata || {})

  const currentKind = kinds.find(k => k.name === type)

  function handleSave(e: Event) {
    e.preventDefault()
    onSave({ ...thing, content, type, metadata })
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: 'rgba(0,0,0,0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: 'white',
          borderRadius: 12,
          padding: 24,
          width: '100%',
          maxWidth: 500,
          maxHeight: '80vh',
          overflow: 'auto',
        }}
        onClick={e => e.stopPropagation()}
      >
        <h2 style={{ margin: '0 0 20px', fontSize: 20 }}>Edit Thing</h2>
        <form onSubmit={handleSave}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500 }}>Kind</label>
            <select
              value={type}
              onChange={e => {
                setType((e.target as HTMLSelectElement).value)
                setMetadata({})
              }}
              style={{
                width: '100%',
                padding: '10px 14px',
                border: '1px solid #ddd',
                borderRadius: 6,
                fontSize: 14,
              }}
            >
              {kinds.map(kind => (
                <option key={kind.id} value={kind.name}>{kind.icon} {kind.name}</option>
              ))}
            </select>
          </div>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500 }}>Content</label>
            <textarea
              value={content}
              onInput={e => setContent((e.target as HTMLTextAreaElement).value)}
              rows={4}
              style={{
                width: '100%',
                padding: '10px 14px',
                border: '1px solid #ddd',
                borderRadius: 6,
                fontSize: 14,
                resize: 'vertical',
                boxSizing: 'border-box',
              }}
            />
          </div>

          {/* Kind attributes */}
          {currentKind?.attributes && currentKind.attributes.length > 0 && (
            <div style={{ marginBottom: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <label style={{ fontSize: 14, fontWeight: 500 }}>Attributes</label>
              {currentKind.attributes.map(attr => (
                <AttributeInput
                  key={attr.name}
                  attribute={attr}
                  value={metadata[attr.name]}
                  onChange={val => setMetadata({ ...metadata, [attr.name]: val })}
                />
              ))}
            </div>
          )}

          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '10px 20px',
                background: '#f5f5f5',
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
                background: '#1a1a1a',
                color: 'white',
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

// Edit Kind Modal
function EditKindModal({
  kind,
  onSave,
  onClose,
  usedEmojis,
}: {
  kind: Kind
  onSave: (k: Kind) => void
  onClose: () => void
  usedEmojis: string[]
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
        background: 'rgba(0,0,0,0.5)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        zIndex: 1000,
      }}
      onClick={onClose}
    >
      <div
        style={{
          background: 'white',
          borderRadius: 12,
          padding: 24,
          width: '100%',
          maxWidth: 600,
          maxHeight: '80vh',
          overflow: 'auto',
        }}
        onClick={e => e.stopPropagation()}
      >
        <h2 style={{ margin: '0 0 20px', fontSize: 20 }}>Edit Kind: {kind.name}</h2>
        <form onSubmit={handleSave}>
          <div style={{ display: 'flex', gap: 12, marginBottom: 16, alignItems: 'flex-end' }}>
            <div>
              <label style={{ display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500 }}>Icon</label>
              <EmojiPicker value={icon} onChange={setIcon} usedEmojis={usedEmojis} />
            </div>
            <div style={{ flex: 1 }}>
              <label style={{ display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500 }}>Name</label>
              <input
                type="text"
                value={name}
                onInput={e => setName((e.target as HTMLInputElement).value)}
                style={{ width: '100%', padding: '10px 14px', border: '1px solid #ddd', borderRadius: 6, boxSizing: 'border-box' }}
              />
            </div>
          </div>

          {/* Template selector */}
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500 }}>Display Template</label>
            <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
              {TEMPLATES.map(t => (
                <button
                  key={t.id}
                  type="button"
                  onClick={() => setTemplate(t.id as Kind['template'])}
                  style={{
                    padding: '8px 14px',
                    border: template === t.id ? '2px solid #1a1a1a' : '1px solid #ddd',
                    borderRadius: 6,
                    background: template === t.id ? '#f5f5f5' : 'white',
                    cursor: 'pointer',
                    fontSize: 13,
                  }}
                  title={t.description}
                >
                  {t.name}
                </button>
              ))}
            </div>
            <p style={{ fontSize: 12, color: '#666', marginTop: 4 }}>
              {TEMPLATES.find(t => t.id === template)?.description}
            </p>
          </div>

          <div style={{ marginBottom: 20 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 12 }}>
              <label style={{ fontSize: 14, fontWeight: 500 }}>Attributes</label>
              <button
                type="button"
                onClick={addAttribute}
                style={{
                  padding: '6px 12px',
                  background: '#f5f5f5',
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
              <p style={{ color: '#999', fontSize: 14, textAlign: 'center', padding: 20, background: '#f9f9f9', borderRadius: 8 }}>
                No attributes. Add one to define fields for this kind.
              </p>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {attributes.map((attr, i) => (
                  <div key={i} style={{ padding: 12, background: '#f9f9f9', borderRadius: 8 }}>
                    <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginBottom: attr.type === 'select' ? 8 : 0 }}>
                      <input
                        type="text"
                        value={attr.name}
                        placeholder="Field name"
                        onInput={e => updateAttribute(i, 'name', (e.target as HTMLInputElement).value)}
                        style={{ flex: 1, padding: '8px 10px', border: '1px solid #ddd', borderRadius: 4, fontSize: 13 }}
                      />
                      <select
                        value={attr.type}
                        onChange={e => updateAttribute(i, 'type', (e.target as HTMLSelectElement).value)}
                        style={{ padding: '8px 10px', border: '1px solid #ddd', borderRadius: 4, fontSize: 13 }}
                      >
                        <option value="text">Text</option>
                        <option value="number">Number</option>
                        <option value="date">Date</option>
                        <option value="url">URL</option>
                        <option value="checkbox">Checkbox</option>
                        <option value="select">Select</option>
                      </select>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 13, whiteSpace: 'nowrap' }}>
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
                        style={{ padding: '4px 8px', background: 'none', border: 'none', color: '#c44', cursor: 'pointer', fontSize: 16 }}
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
                          style={{ width: '100%', padding: '8px 10px', border: '1px solid #ddd', borderRadius: 4, fontSize: 13, boxSizing: 'border-box' }}
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
                background: '#f5f5f5',
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
                background: '#1a1a1a',
                color: 'white',
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
