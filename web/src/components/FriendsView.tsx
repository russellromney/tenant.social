import { useState, useEffect } from 'preact/hooks'
import { Theme } from '../theme'
import { Follow, RemoteProfile } from '../types'
import { apiUrl } from '../api'

interface FriendsViewProps {
  theme: Theme
  isMobile: boolean
}

export function FriendsView({
  theme,
  isMobile,
}: FriendsViewProps) {
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
