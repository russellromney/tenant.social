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
      <h2 className="text-xl mb-4" style={{ color: theme.text }}>Friends</h2>

      {/* Mutuals Section - Real Friends */}
      {mutuals.length > 0 && (
        <div className="p-5 rounded-xl mb-6" style={{ background: theme.bgCard, border: `1px solid ${theme.accent}` }}>
          <h3 className="text-base mb-4" style={{ color: theme.accent }}>
            Mutuals ({mutuals.length})
          </h3>
          <div className="flex flex-col gap-3">
            {mutuals.map(follow => (
              <div
                key={follow.id}
                className="flex justify-between items-center px-4 py-3 rounded-lg"
                style={{ background: theme.bgHover }}
              >
                <div>
                  <a
                    href={getFullUrl(follow.remote_endpoint)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-medium no-underline"
                    style={{ color: theme.link }}
                  >
                    {getFullUrl(follow.remote_endpoint)}
                  </a>
                  <div className="text-xs" style={{ color: theme.textMuted }}>
                    Friends since {new Date(follow.created_at).toLocaleDateString()}
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Add Friend Section */}
      <div className="p-5 rounded-xl mb-6" style={{ background: theme.bgCard, border: `1px solid ${theme.border}` }}>
        <h3 className="text-base mb-2" style={{ color: theme.text }}>Add Friend</h3>
        <p className="text-sm mb-4" style={{ color: theme.textMuted }}>
          Enter a username or URL to follow someone.
        </p>

        <form onSubmit={addFriend} className={`flex gap-2 ${isMobile ? 'flex-col' : 'flex-row'}`}>
          <input
            type="text"
            value={friendUrl}
            onInput={e => setFriendUrl((e.target as HTMLInputElement).value)}
            placeholder="bob or /bob or http://tenant.social/alice"
            className="flex-1 px-3.5 py-2.5 rounded-md text-sm"
            style={{
              border: `1px solid ${theme.borderInput}`,
              background: theme.bgInput,
              color: theme.text,
            }}
          />
          <button
            type="submit"
            disabled={adding || !friendUrl.trim()}
            className="px-5 py-2.5 rounded-md text-sm font-medium border-0"
            style={{
              background: adding ? theme.textDisabled : theme.accent,
              color: adding ? theme.textSubtle : theme.accentText,
              cursor: adding ? 'not-allowed' : 'pointer',
            }}
          >
            {adding ? 'Adding...' : 'Add Friend'}
          </button>
        </form>

        {error && (
          <p className="text-sm mt-3" style={{ color: '#ef4444' }}>{error}</p>
        )}
        {success && (
          <p className="text-sm mt-3" style={{ color: '#22c55e' }}>{success}</p>
        )}
      </div>

      {/* Following Section */}
      <div className="p-5 rounded-xl mb-4" style={{ background: theme.bgCard, border: `1px solid ${theme.border}` }}>
        <h3 className="text-base mb-4" style={{ color: theme.text }}>
          Following ({following.length})
        </h3>

        {loading ? (
          <p className="text-sm" style={{ color: theme.textMuted }}>Loading...</p>
        ) : following.length === 0 ? (
          <p className="text-sm" style={{ color: theme.textMuted }}>
            You're not following anyone yet. Add a friend above!
          </p>
        ) : (
          <div className="flex flex-col gap-3">
            {following.map(follow => (
              <div
                key={follow.id}
                className="flex justify-between items-center px-4 py-3 rounded-lg"
                style={{ background: theme.bgHover }}
              >
                <div>
                  <a
                    href={getFullUrl(follow.remote_endpoint)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="font-medium no-underline"
                    style={{ color: theme.link }}
                  >
                    {getFullUrl(follow.remote_endpoint)}
                  </a>
                  <div className="text-xs" style={{ color: theme.textMuted }}>
                    Since {new Date(follow.created_at).toLocaleDateString()}
                  </div>
                </div>
                <button
                  onClick={() => unfollowUser(follow.following_id)}
                  className="px-3 py-1.5 rounded-md text-xs cursor-pointer"
                  style={{
                    background: 'transparent',
                    color: theme.textMuted,
                    border: `1px solid ${theme.border}`,
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
      <div className="p-5 rounded-xl" style={{ background: theme.bgCard, border: `1px solid ${theme.border}` }}>
        <h3 className="text-base mb-4" style={{ color: theme.text }}>
          Followers ({followers.length})
        </h3>

        {loading ? (
          <p className="text-sm" style={{ color: theme.textMuted }}>Loading...</p>
        ) : followers.length === 0 ? (
          <p className="text-sm" style={{ color: theme.textMuted }}>
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
            <div className="flex flex-col gap-4">
              {/* Active Followers */}
              {activeFollowers.length > 0 && (
                <div>
                  <div className="text-xs font-medium mb-2" style={{ color: theme.accent }}>
                    Active ({activeFollowers.length})
                  </div>
                  <div className="flex flex-col gap-2">
                    {activeFollowers.map(follow => (
                      <div
                        key={follow.id}
                        className="flex justify-between items-center px-4 py-3 rounded-lg"
                        style={{
                          background: theme.bgHover,
                          borderLeft: `3px solid ${theme.accent}`,
                        }}
                      >
                        <div>
                          <a
                            href={getFullUrl(follow.remote_endpoint)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-medium no-underline"
                            style={{ color: theme.link }}
                          >
                            {getFullUrl(follow.remote_endpoint)}
                          </a>
                          <div className="text-xs" style={{ color: theme.textMuted }}>
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
                  <div className="text-xs font-medium mb-2" style={{ color: theme.textMuted }}>
                    Lapsed ({lapsedFollowers.length})
                  </div>
                  <div className="flex flex-col gap-2">
                    {lapsedFollowers.map(follow => (
                      <div
                        key={follow.id}
                        className="flex justify-between items-center px-4 py-3 rounded-lg opacity-70"
                        style={{ background: theme.bgHover }}
                      >
                        <div>
                          <a
                            href={getFullUrl(follow.remote_endpoint)}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-medium no-underline"
                            style={{ color: theme.link }}
                          >
                            {getFullUrl(follow.remote_endpoint)}
                          </a>
                          <div className="text-xs" style={{ color: theme.textMuted }}>
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
