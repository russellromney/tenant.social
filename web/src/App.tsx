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
    <div className="flex min-h-screen font-sans" style={{ background: theme.bg }}>
      {/* Sidebar */}
      <div className="w-[220px] fixed h-screen overflow-y-auto py-5 border-r" style={{
        background: theme.bgCard,
        borderRightColor: theme.border,
      }}>
        <a href={routeHref('/')} className="block no-underline px-5 pb-5" style={{ color: theme.text }}>
          <h1 className="text-2xl font-bold m-0">tenant</h1>
        </a>
        <nav>
          {sections.map(s => (
            <a
              key={s.id}
              href={s.route}
              className="block py-2.5 px-5 no-underline text-sm border-l-[3px]"
              style={{
                color: section === s.id ? theme.accent : theme.textSecondary,
                background: section === s.id ? theme.bgMuted : 'transparent',
                borderLeftColor: section === s.id ? theme.accent : 'transparent',
                fontWeight: section === s.id ? 600 : 400,
              }}
            >
              {s.label}
            </a>
          ))}
        </nav>
      </div>

      {/* Main content */}
      <div className="ml-[220px] flex-1">
        <div className="max-w-[800px] mx-auto p-10">
          <div className="flex justify-between items-center mb-8">
            <h2 className="text-[28px] font-semibold m-0" style={{ color: theme.text }}>{sectionTitles[section]}</h2>
            <a
              href={routeHref('/')}
              className="px-4 py-2 rounded-md text-sm no-underline"
              style={{
                background: theme.bgHover,
                color: theme.textSecondary,
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
    <div className="flex items-center justify-center min-h-screen font-sans flex-col" style={{ background: theme.bg }}>
      <div className="w-full max-w-[380px] p-8 rounded-xl" style={{
        background: theme.bgCard,
        boxShadow: `0 4px 12px ${theme.shadow}`,
      }}>
        <h1 className="text-4xl font-bold m-0 mb-2 text-center" style={{ color: theme.text }}>tenant.social</h1>
        <p className="text-sm mb-5 text-center" style={{ color: theme.textMuted }}>
          your corner of the internet
        </p>
        <p className="text-sm mb-4 text-center font-medium" style={{ color: theme.textSecondary }}>
          {mode === 'register' ? 'Create your account' : 'Sign in to continue'}
        </p>
        <form onSubmit={handleSubmit}>
          <input
            type="text"
            value={username}
            onInput={e => setUsername((e.target as HTMLInputElement).value)}
            placeholder="Username"
            autoFocus
            className="w-full px-3.5 py-3 rounded-md text-base box-border mb-3 border"
            style={{
              borderColor: theme.borderInput,
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
              className="w-full px-3.5 py-3 rounded-md text-base box-border mb-3 border"
              style={{
                borderColor: theme.borderInput,
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
            className="w-full px-3.5 py-3 rounded-md text-base box-border mb-3 border"
            style={{
              borderColor: error ? theme.error : theme.borderInput,
              background: theme.bgInput,
              color: theme.text,
            }}
          />
          {error && (
            <p className="text-[13px] m-0 mb-3" style={{ color: theme.error }}>{error}</p>
          )}
          <button
            type="submit"
            disabled={!isValid || loading}
            className="w-full px-5 py-3 border-none rounded-md text-base font-semibold mb-4"
            style={{
              background: isValid && !loading ? theme.accent : theme.textDisabled,
              color: isValid && !loading ? theme.accentText : theme.textSubtle,
              cursor: isValid && !loading ? 'pointer' : 'not-allowed',
            }}
          >
            {loading
              ? (mode === 'register' ? 'Creating account...' : 'Signing in...')
              : (mode === 'register' ? 'Create account' : 'Sign in')}
          </button>
        </form>
        {/* Only show toggle if registration is enabled */}
        {showRegisterOption && (
          <p className="text-center text-sm m-0" style={{ color: theme.textMuted }}>
            {mode === 'register' ? (
              <>Already have an account? <button onClick={() => { setMode('login'); setError('') }} className="bg-none border-none cursor-pointer text-sm p-0" style={{ color: theme.link }}>Sign in</button></>
            ) : (
              <>Don't have an account? <button onClick={() => { setMode('register'); setError('') }} className="bg-none border-none cursor-pointer text-sm p-0" style={{ color: theme.link }}>Register</button></>
            )}
          </p>
        )}
        {/* For single-tenant instances, no registration option */}
        {!showRegisterOption && mode === 'login' && (
          <p className="text-center text-xs m-0" style={{ color: theme.textSubtle }}>
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
    <div className="max-w-[700px] mx-auto font-sans min-h-screen" style={{
      padding: isMobile ? 12 : 20,
      background: theme.bg,
      color: theme.text
    }}>
      {/* Header */}
      <div className="flex justify-between items-center gap-2" style={{ marginBottom: isMobile ? 16 : 24 }}>
        <div className="flex items-center gap-3">
          <button
            onClick={onBack}
            className="bg-none border-none cursor-pointer text-xl px-2 py-1"
            style={{ color: theme.textMuted }}
          >
            ←
          </button>
          <a href={routeHref('/')} className="no-underline" style={{ color: theme.text }}>
            <h1 className="font-bold m-0" style={{ fontSize: isMobile ? 22 : 28 }}>tenant</h1>
          </a>
        </div>
        <div className="flex items-center" style={{ gap: isMobile ? 4 : 8 }}>
          <button
            onClick={toggleTheme}
            className="border-none rounded-md cursor-pointer text-sm"
            style={{
              padding: isMobile ? '6px 10px' : '8px 12px',
              background: theme.bgHover,
              color: theme.textMuted,
            }}
          >
            {isDark ? '☀️' : '🌙'}
          </button>
          <button
            onClick={onLogout}
            className="border-none rounded-md cursor-pointer text-sm"
            style={{
              padding: isMobile ? '6px 10px' : '8px 12px',
              background: theme.bgHover,
              color: theme.textMuted,
            }}
          >
            Logout
          </button>
        </div>
      </div>

      {/* Content */}
      {loading ? (
        <p className="text-center" style={{ color: theme.textMuted }}>Loading...</p>
      ) : error ? (
        <p className="text-center" style={{ color: theme.error }}>{error}</p>
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
            <div className="mt-8 pt-6 border-t" style={{ borderTopColor: theme.border }}>
              <h2 className="text-lg font-semibold mt-0 mb-4" style={{ color: theme.text }}>
                Backlinks ({backlinks.length})
              </h2>
              <div className="grid gap-3" style={{ gridTemplateColumns: isMobile ? '1fr' : 'repeat(auto-fill, minmax(250px, 1fr))' }}>
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
    <div className="flex min-h-screen font-sans" style={{ background: theme.bg, color: theme.text }}>
      {/* Side Menu */}
      <div
        className="flex-shrink-0 flex flex-col fixed top-0 bottom-0 z-[100] border-r"
        style={{
          width: sidebarWidth,
          background: theme.bgCard,
          borderRightColor: theme.border,
          left: isMobile ? 0 : `calc(50% - ${350 + sidebarWidth}px)`,
        }}
      >
        {/* Logo */}
        <a
          href={routeHref('/')}
          className="no-underline flex items-center border-b"
          style={{
            padding: isMobile ? '16px 0' : '20px 16px',
            color: theme.text,
            justifyContent: isMobile ? 'center' : 'flex-start',
            borderBottomColor: theme.border,
          }}
        >
          <span className="font-bold" style={{ fontSize: isMobile ? 20 : 22 }}>
            {isMobile ? 't' : 'tenant'}
          </span>
        </a>

        {/* Navigation */}
        <nav className="flex-1 py-3 flex flex-col gap-1">
          {navItems.map(item => (
            <a
              key={item.href}
              href={routeHref(item.href)}
              className="flex items-center gap-3 no-underline text-sm transition-all duration-150"
              style={{
                padding: isMobile ? '12px 0' : '10px 16px',
                justifyContent: isMobile ? 'center' : 'flex-start',
                background: item.active ? theme.accent : 'transparent',
                color: item.active ? theme.accentText : theme.text,
                borderRadius: isMobile ? 0 : 6,
                margin: isMobile ? 0 : '0 8px',
                fontWeight: item.active ? 600 : 400,
              }}
              onMouseEnter={e => !item.active && (e.currentTarget.style.background = theme.bgHover)}
              onMouseLeave={e => !item.active && (e.currentTarget.style.background = 'transparent')}
            >
              <span className="text-lg">{item.icon}</span>
              {!isMobile && <span>{item.label}</span>}
            </a>
          ))}
        </nav>

        {/* Bottom actions */}
        <div className="flex flex-col gap-1 border-t" style={{
          padding: isMobile ? '12px 0' : '12px 8px',
          borderTopColor: theme.border
        }}>
          <button
            onClick={toggleTheme}
            className="flex items-center gap-3 bg-transparent border-none text-sm cursor-pointer w-full"
            style={{
              padding: isMobile ? '12px 0' : '10px 16px',
              justifyContent: isMobile ? 'center' : 'flex-start',
              color: theme.textMuted,
              borderRadius: isMobile ? 0 : 6,
            }}
            title={isDark ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            <span className="text-lg">{isDark ? '☀️' : '🌙'}</span>
            {!isMobile && <span>{isDark ? 'Light' : 'Dark'}</span>}
          </button>
          <button
            onClick={handleLogout}
            className="flex items-center gap-3 bg-transparent border-none text-sm cursor-pointer w-full"
            style={{
              padding: isMobile ? '12px 0' : '10px 16px',
              justifyContent: isMobile ? 'center' : 'flex-start',
              color: theme.textMuted,
              borderRadius: isMobile ? 0 : 6,
            }}
          >
            <span className="text-lg">🚪</span>
            {!isMobile && <span>Logout</span>}
          </button>
        </div>

        {/* Footer Links */}
        {!isMobile && (
          <div className="px-4 py-3 border-t text-[11px]" style={{
            borderTopColor: theme.border,
            color: theme.textSubtle
          }}>
            <div className="mb-2" style={{ color: theme.textMuted }}>
              Your personal social data platform
            </div>
            <div className="flex flex-col gap-1 mb-2">
              <a href={routeHref('/docs')} className="no-underline" style={{ color: theme.textMuted }}>About</a>
              <a href={routeHref('/docs/api')} className="no-underline" style={{ color: theme.textMuted }}>API</a>
              <a href={routeHref('/docs/deployment')} className="no-underline" style={{ color: theme.textMuted }}>Deploy</a>
              <a href="https://github.com/russellromney/tenant.social" target="_blank" rel="noopener noreferrer" className="no-underline" style={{ color: theme.textMuted }}>GitHub</a>
            </div>
            <div>Made with ❤️ in NYC by <a href="https://russellromney.com" target="_blank" rel="noopener noreferrer" className="no-underline" style={{ color: theme.link }}>me</a></div>
          </div>
        )}
      </div>

      {/* Main Content */}
      <div
        className="flex-1 flex"
        style={{
          marginLeft: isMobile ? sidebarWidth : `calc(50% - ${350}px)`,
          justifyContent: isMobile ? 'center' : 'flex-start',
        }}
      >
      <div className="w-full max-w-[700px]" style={{ padding: isMobile ? 12 : 20 }}>
        {/* Back button for sub-pages */}
        {isSubPage && (
          <div className="mb-4">
            <a
              href={routeHref('/')}
              className="inline-flex items-center gap-1.5 px-4 py-2 border-none rounded-md text-sm cursor-pointer no-underline"
              style={{
                background: theme.bgHover,
                color: theme.text,
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
          <div className="flex gap-2 mb-4" style={{ flexDirection: isMobile ? 'column' : 'row' }}>
            <input
              type="text"
              value={searchQuery}
              onInput={e => setSearchQuery((e.target as HTMLInputElement).value)}
              placeholder="Search things..."
              className="flex-1 rounded-md text-sm border"
              style={{
                padding: isMobile ? '8px 12px' : '10px 14px',
                borderColor: theme.borderInput,
                background: theme.bgInput,
                color: theme.text,
              }}
            />
            <select
              value={filterKind}
              onChange={e => setFilterKind((e.target as HTMLSelectElement).value)}
              className="rounded-md text-sm border"
              style={{
                padding: isMobile ? '8px 12px' : '10px 14px',
                borderColor: theme.borderInput,
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
          <form onSubmit={createThing} className="mb-8">
            <div
              className="rounded-2xl overflow-hidden border-2 transition-all duration-150"
              style={{
                background: theme.bgCard,
                borderColor: theme.borderStrong,
              }}
            >
              {/* Top toolbar - Kind selector */}
              <div
                className="flex justify-between items-center px-3 py-2.5 border-b"
                style={{ borderBottomColor: theme.bgMuted }}
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
              <div className="px-4 py-3">
                <input
                  type="text"
                  value={newContent}
                  onInput={e => setNewContent((e.target as HTMLInputElement).value)}
                  placeholder="What's on your mind?"
                  className="w-full p-0 border-none text-[17px] leading-relaxed outline-none bg-transparent box-border font-inherit"
                  style={{ color: theme.text }}
                />

                {/* Kind-specific attributes */}
                {currentKind?.attributes && currentKind.attributes.length > 0 && (
                  <div className="flex flex-col gap-2 mt-3 pt-3 border-t" style={{ borderTopColor: theme.bgMuted }}>
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
                className="flex justify-between items-center px-3 py-2.5 border-t"
                style={{
                  background: theme.bgToolbar,
                  borderTopColor: theme.bgMuted,
                }}
              >
                <div className="flex items-center gap-2">
                  <button
                    type="button"
                    className="flex items-center gap-1 px-3 py-1.5 bg-transparent border-none rounded-md text-sm"
                    style={{
                      cursor: uploading ? 'wait' : 'pointer',
                      color: theme.textMuted,
                    }}
                    onClick={() => setShowPhotoModal(true)}
                    disabled={uploading}
                  >
                    <span className="text-lg">📷</span>
                    <span>{uploading ? 'Uploading...' : 'Photo'}</span>
                    {selectedPhotos.length > 0 && (
                      <span className="rounded-full w-5 h-5 flex items-center justify-center text-xs font-semibold ml-1" style={{
                        background: theme.accent,
                        color: theme.accentText,
                      }}>
                        {selectedPhotos.length}
                      </span>
                    )}
                  </button>
                  <select
                    value={newVisibility}
                    onChange={e => setNewVisibility((e.target as HTMLSelectElement).value as 'private' | 'friends' | 'public')}
                    className="px-2.5 py-1.5 rounded-md text-[13px] cursor-pointer font-inherit border"
                    style={{
                      background: theme.bgMuted,
                      borderColor: theme.border,
                      color: theme.text,
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
                  className="px-5 py-2 border-none rounded-full text-sm font-semibold transition-all duration-150"
                  style={{
                    background: newContent.trim() ? theme.accent : theme.textDisabled,
                    color: newContent.trim() ? theme.accentText : theme.textSubtle,
                    cursor: newContent.trim() ? 'pointer' : 'not-allowed',
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
            <div className="flex flex-col gap-3">
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
          className="fixed top-0 left-0 right-0 bottom-0 flex items-center justify-center z-[1000] p-4"
          style={{ background: 'rgba(0, 0, 0, 0.5)' }}
          onClick={() => {
            if (!uploading) {
              setShowPhotoModal(false)
              // Keep photos as draft - don't clear!
            }
          }}
        >
          <div
            className="rounded-xl p-6 max-w-[600px] max-h-[90vh] overflow-auto w-full transition-all duration-200"
            style={{
              background: dragOverModal ? theme.bgHover : theme.bg,
              border: dragOverModal ? `2px dashed ${theme.accent}` : 'none',
            }}
            onClick={e => e.stopPropagation()}
            onDragOver={handleDragOverModal as any}
            onDragLeave={handleDragLeaveModal as any}
            onDrop={handleDropOnModal as any}
          >
            <div className="flex justify-between items-center mb-5">
              <h2 className="m-0 text-xl font-semibold" style={{ color: theme.text }}>
                📷 Upload Photos
              </h2>
              <div className="flex gap-2">
                {selectedPhotos.length > 0 && (
                  <button
                    onClick={() => {
                      selectedPhotos.forEach(p => URL.revokeObjectURL(p.preview))
                      setSelectedPhotos([])
                    }}
                    disabled={uploading}
                    className="bg-none border-none text-[13px] font-medium p-0"
                    style={{
                      color: theme.error,
                      cursor: uploading ? 'not-allowed' : 'pointer',
                      opacity: uploading ? 0.5 : 1,
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
                  className="bg-none border-none text-2xl"
                  style={{
                    cursor: uploading ? 'not-allowed' : 'pointer',
                    opacity: uploading ? 0.5 : 1,
                  }}
                >
                  ✕
                </button>
              </div>
            </div>

            {/* Photo previews and captions */}
            <div className="mb-5">
              {selectedPhotos.length > 0 ? (
                <div className="flex flex-col gap-4">
                  {selectedPhotos.map((photo, index) => (
                    <div
                      key={index}
                      className="rounded-lg p-3 flex gap-3 items-start"
                      style={{ background: theme.bgMuted }}
                    >
                      <img
                        src={photo.preview}
                        alt={`Photo ${index + 1}`}
                        className="w-20 h-20 object-cover rounded-md flex-shrink-0"
                      />
                      <div className="flex-1 min-w-0">
                        <label className="block mb-1.5 text-xs" style={{ color: theme.textMuted }}>
                          Caption (optional)
                        </label>
                        <input
                          type="text"
                          value={photo.caption}
                          onChange={e => updatePhotoCaption(index, e.currentTarget.value)}
                          placeholder="Add a caption..."
                          disabled={uploading}
                          className="w-full px-2.5 py-2 rounded-md text-[13px] border"
                          style={{
                            borderColor: theme.borderInput,
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
                        className="bg-none border-none text-lg"
                        style={{
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
                <div className="text-center p-10" style={{ color: theme.textMuted }}>
                  <p className="m-0 mb-2 text-sm">📁 Drag and drop photos here</p>
                  <p className="m-0 mb-3 text-[13px]" style={{ color: theme.textSubtle }}>or use the Photo button to select files</p>
                  <input
                    type="file"
                    accept="image/*,video/*"
                    multiple
                    onChange={handlePhotoInputChange}
                    className="hidden"
                    disabled={uploading}
                    id="photo-modal-input"
                  />
                  <button
                    type="button"
                    className="inline-block px-4 py-2 rounded-md text-[13px] font-medium border-none"
                    style={{
                      background: theme.accent,
                      color: theme.accentText,
                      cursor: uploading ? 'not-allowed' : 'pointer',
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
            <div className="mb-5 flex flex-col gap-3">
              <div>
                <label className="block mb-1.5 text-xs font-medium" style={{ color: theme.textMuted }}>
                  Post content (optional)
                </label>
                <textarea
                  value={photoContent}
                  onChange={e => setPhotoContent(e.currentTarget.value)}
                  placeholder="Add a caption for your gallery..."
                  disabled={uploading}
                  className="w-full px-3 py-2.5 rounded-md text-[13px] font-inherit min-h-[60px] resize-y border"
                  style={{
                    borderColor: theme.borderInput,
                    background: theme.bgInput,
                    color: theme.text,
                    opacity: uploading ? 0.5 : 1,
                    cursor: uploading ? 'not-allowed' : 'text',
                  }}
                />
              </div>

              <div>
                <label className="block mb-1.5 text-xs font-medium" style={{ color: theme.textMuted }}>
                  Visibility
                </label>
                <select
                  value={photoVisibility}
                  onChange={e => setPhotoVisibility(e.currentTarget.value as 'private' | 'friends' | 'public')}
                  disabled={uploading}
                  className="w-full px-2.5 py-2 rounded-md text-[13px] border"
                  style={{
                    borderColor: theme.borderInput,
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
            <div className="flex gap-3 justify-end">
              <button
                onClick={() => {
                  setShowPhotoModal(false)
                  // Keep photos as draft - don't clear!
                }}
                disabled={uploading}
                className="px-4 py-2 border-none rounded-md text-[13px] font-medium"
                style={{
                  background: theme.bgMuted,
                  color: theme.text,
                  cursor: uploading ? 'not-allowed' : 'pointer',
                  opacity: uploading ? 0.5 : 1,
                }}
              >
                Close
              </button>
              <button
                type="button"
                onClick={submitPhotoUpload}
                disabled={uploading || selectedPhotos.length === 0}
                className="px-4 py-2 border-none rounded-md text-[13px] font-semibold"
                style={{
                  background: uploading || selectedPhotos.length === 0 ? theme.textDisabled : theme.accent,
                  color: uploading || selectedPhotos.length === 0 ? theme.textSubtle : theme.accentText,
                  cursor: uploading || selectedPhotos.length === 0 ? 'not-allowed' : 'pointer',
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
