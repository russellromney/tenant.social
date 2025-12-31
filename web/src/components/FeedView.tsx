import { useState, useEffect } from 'preact/hooks'
import { Theme } from '../theme'
import { Kind, Thing, FriendFeedItem, Follow } from '../types'
import { apiUrl, routeHref } from '../api'

export function FeedView({
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

