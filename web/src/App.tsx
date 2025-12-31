import { useState, useEffect } from 'preact/hooks'
import { useTheme, Theme } from './theme.tsx'
import { PublicHomePage } from './PublicHomePage.tsx'
import { apiUrl, getRoute, navigateTo, routeHref, setupClientSideNavigation } from './api'
import { AboutContent, APIDocsContent, DeploymentContent, AIAgentsContent } from './docs'
import {
  Kind, Thing, DEFAULT_KINDS, AuthStatus
} from './types'
import { useRoute, useIsMobile } from './hooks'
import { KindSelector, Footer, EditThingModal, EditKindModal, AttributeInput, SettingsPage, ThingCard, CommentsSection, BookmarksView, FeedView } from './components'

// Setup client-side navigation for SPA routing
setupClientSideNavigation()

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

export default App
