import { useState, useEffect } from 'preact/hooks'
import { Theme } from './theme.tsx'
import { Markdown } from './Markdown.tsx'
import { getBasePath } from './api'

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
  visibility: string
  created_at: string
  updated_at: string
  photos?: Photo[]
}

interface User {
  id: string
  username: string
  email: string
  display_name: string
  bio: string
  avatar_url: string
  is_admin: boolean
  created_at: string
  updated_at: string
}

interface PublicHomePageProps {
  theme: Theme
  onLogin: () => void
}

export function PublicHomePage({ theme, onLogin }: PublicHomePageProps) {
  const [profile, setProfile] = useState<User | null>(null)
  const [things, setThings] = useState<Thing[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const basePath = getBasePath()

  useEffect(() => {
    const fetchPublicData = async () => {
      try {
        setLoading(true)

        // Fetch public profile
        const profileRes = await fetch(`${basePath}/api/public/profile`)
        if (profileRes.ok) {
          const profileData = await profileRes.json()
          setProfile(profileData)
        }

        // Fetch public things
        const thingsRes = await fetch(`${basePath}/api/public/things?limit=20`)
        if (thingsRes.ok) {
          const thingsData = await thingsRes.json()
          setThings(thingsData)
        }

        setLoading(false)
      } catch (err) {
        console.error('Error fetching public data:', err)
        setError('Failed to load public content')
        setLoading(false)
      }
    }

    fetchPublicData()
  }, [basePath])

  if (loading) {
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100vh',
        fontFamily: 'system-ui, sans-serif',
        background: theme.bg,
      }}>
        <div style={{ color: theme.textMuted }}>Loading...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        minHeight: '100vh',
        fontFamily: 'system-ui, sans-serif',
        background: theme.bg,
        flexDirection: 'column',
        gap: 16,
      }}>
        <div style={{ color: theme.error }}>{error}</div>
        <button
          onClick={onLogin}
          style={{
            padding: '12px 24px',
            background: theme.accent,
            color: theme.accentText,
            border: 'none',
            borderRadius: 8,
            cursor: 'pointer',
            fontSize: 14,
            fontWeight: 600,
          }}
        >
          Login
        </button>
      </div>
    )
  }

  return (
    <div style={{
      minHeight: '100vh',
      fontFamily: 'system-ui, sans-serif',
      background: theme.bg,
      color: theme.text,
    }}>
      {/* Header with login button */}
      <div style={{
        background: theme.bgCard,
        borderBottom: `1px solid ${theme.border}`,
        padding: '16px 24px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
      }}>
        <h1 style={{
          fontSize: 24,
          fontWeight: 700,
          margin: 0,
          color: theme.accent,
        }}>
          {profile?.display_name || 'tenant.social'}
        </h1>
        <button
          onClick={onLogin}
          style={{
            padding: '8px 16px',
            background: theme.accent,
            color: theme.accentText,
            border: 'none',
            borderRadius: 6,
            cursor: 'pointer',
            fontSize: 14,
            fontWeight: 600,
          }}
        >
          Login
        </button>
      </div>

      {/* Main content */}
      <div style={{
        maxWidth: 800,
        margin: '0 auto',
        padding: 24,
      }}>
        {/* Profile section */}
        {profile && profile.bio && (
          <div style={{
            background: theme.bgCard,
            padding: 24,
            borderRadius: 12,
            marginBottom: 24,
            boxShadow: `0 2px 8px ${theme.shadow}`,
          }}>
            <h2 style={{
              fontSize: 20,
              fontWeight: 600,
              margin: '0 0 8px',
            }}>
              About
            </h2>
            <div style={{ color: theme.textMuted, lineHeight: 1.6 }}>
              {profile.bio}
            </div>
          </div>
        )}

        {/* Public things */}
        {things.length > 0 ? (
          <div>
            <h2 style={{
              fontSize: 20,
              fontWeight: 600,
              margin: '0 0 16px',
            }}>
              Public Posts
            </h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
              {things.map(thing => (
                <div
                  key={thing.id}
                  style={{
                    background: theme.bgCard,
                    padding: 20,
                    borderRadius: 12,
                    boxShadow: `0 2px 8px ${theme.shadow}`,
                  }}
                >
                  {thing.content && (
                    <div style={{
                      color: theme.text,
                      lineHeight: 1.6,
                      marginBottom: thing.photos && thing.photos.length > 0 ? 12 : 0,
                    }}>
                      <Markdown content={thing.content} theme={theme} />
                    </div>
                  )}

                  {/* Photo gallery */}
                  {thing.photos && thing.photos.length > 0 && (
                    <div style={{
                      display: 'grid',
                      gridTemplateColumns: thing.photos.length === 1 ? '1fr' : 'repeat(auto-fit, minmax(200px, 1fr))',
                      gap: 8,
                      marginTop: thing.content ? 12 : 0,
                    }}>
                      {thing.photos.map(photo => (
                        photo.content_type.startsWith('image/') ? (
                          <img
                            key={photo.id}
                            src={`${basePath}/api/photos/${photo.id}`}
                            alt={photo.caption || ''}
                            style={{
                              width: '100%',
                              borderRadius: 8,
                              objectFit: 'cover',
                              aspectRatio: thing.photos!.length === 1 ? 'auto' : '1',
                            }}
                          />
                        ) : photo.content_type.startsWith('video/') ? (
                          <video
                            key={photo.id}
                            src={`${basePath}/api/photos/${photo.id}`}
                            controls
                            style={{
                              width: '100%',
                              borderRadius: 8,
                            }}
                          />
                        ) : null
                      ))}
                    </div>
                  )}

                  <div style={{
                    fontSize: 12,
                    color: theme.textMuted,
                    marginTop: 12,
                  }}>
                    {new Date(thing.created_at).toLocaleDateString('en-US', {
                      month: 'short',
                      day: 'numeric',
                      year: 'numeric',
                    })}
                  </div>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <div style={{
            background: theme.bgCard,
            padding: 32,
            borderRadius: 12,
            textAlign: 'center',
            color: theme.textMuted,
          }}>
            No public posts yet
          </div>
        )}
      </div>

      {/* Footer */}
      <div style={{
        padding: '32px 24px',
        textAlign: 'center',
        color: theme.textMuted,
        fontSize: 14,
      }}>
        Powered by{' '}
        <a
          href="https://tenant.social"
          target="_blank"
          rel="noopener noreferrer"
          style={{ color: theme.accent, textDecoration: 'none' }}
        >
          tenant.social
        </a>
      </div>
    </div>
  )
}
