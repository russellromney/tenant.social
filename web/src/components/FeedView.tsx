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
      <div className="flex justify-between items-center mb-4">
        <h2 className="text-xl m-0" style={{ color: theme.text }}>Feed</h2>
        <button
          onClick={fetchFeed}
          className="px-3 py-1.5 rounded-md border-0 cursor-pointer text-xs"
          style={{
            background: theme.bgHover,
            color: theme.textSecondary,
          }}
        >
          Refresh
        </button>
      </div>

      {loading ? (
        <div className="text-center p-10" style={{ color: theme.textMuted }}>
          Loading feed...
        </div>
      ) : error ? (
        <div className="text-center p-10" style={{ color: '#ef4444' }}>
          {error}
        </div>
      ) : feedItems.length === 0 ? (
        <div className="text-center p-10 rounded-xl" style={{
          background: theme.bgCard,
          border: `1px solid ${theme.border}`,
        }}>
          <p className="text-base m-0 mb-2" style={{ color: theme.textMuted }}>
            Your feed is empty
          </p>
          <p className="text-sm m-0" style={{ color: theme.textSubtle }}>
            Follow some friends to see their posts here!
          </p>
          <a
            href={routeHref('/friends')}
            className="inline-block mt-4 px-5 py-2.5 rounded-md no-underline text-sm font-medium"
            style={{
              background: theme.accent,
              color: theme.accentText,
            }}
          >
            Add Friends
          </a>
        </div>
      ) : (
        <div className="flex flex-col gap-4">
          {feedItems.map(item => {
            const kind = getKind(item.type)
            return (
              <div
                key={item.id}
                className="p-4 rounded-xl"
                style={{
                  background: theme.bgCard,
                  border: `1px solid ${theme.border}`,
                }}
              >
                <div className="flex justify-between items-start mb-2">
                  <div className="flex items-center gap-2">
                    <span className="text-lg">{kind?.icon || '📝'}</span>
                    {item.owner_endpoint && (
                      <a
                        href={item.owner_endpoint}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="no-underline font-medium"
                        style={{ color: theme.link }}
                      >
                        {item.owner_username || item.owner_endpoint}
                      </a>
                    )}
                  </div>
                  <span className="text-xs" style={{ color: theme.textMuted }}>
                    {formatDate(item.created_at)}
                  </span>
                </div>

                <div className="leading-normal" style={{ color: theme.text }}>
                  {item.content}
                </div>

                {/* Photos */}
                {item.photos && item.photos.length > 0 && (
                  <div className="mt-3 flex gap-2 flex-wrap">
                    {item.photos.slice(0, 4).map(photo => (
                      <img
                        key={photo.id}
                        src={item.owner_endpoint
                          ? `${item.owner_endpoint}/api/photos/${photo.id}?size=thumb`
                          : apiUrl(`/api/photos/${photo.id}?size=thumb`)
                        }
                        alt={photo.caption || ''}
                        className="max-h-[200px] object-cover rounded-lg"
                        style={{
                          width: item.photos!.length === 1 ? '100%' : 'calc(50% - 4px)',
                        }}
                      />
                    ))}
                  </div>
                )}

                <div className="mt-2 text-xs flex gap-3" style={{ color: theme.textMuted }}>
                  <span>{item.visibility === 'public' ? '🌐 Public' : '👥 Friends'}</span>
                  {(item.comment_count ?? 0) > 0 && (
                    <span>💬 {item.comment_count} {item.comment_count === 1 ? 'reply' : 'replies'}</span>
                  )}
                </div>

                {/* Top Replies Preview */}
                {item.top_replies && item.top_replies.length > 0 && (
                  <div className="mt-3 p-3 rounded-lg" style={{
                    background: theme.bgSubtle,
                    borderLeft: `3px solid ${theme.border}`,
                  }}>
                    {item.top_replies.map((reply, idx) => (
                      <div
                        key={reply.id}
                        className={idx < item.top_replies!.length - 1 ? 'pb-2 mb-2' : ''}
                        style={{
                          borderBottom: idx < item.top_replies!.length - 1 ? `1px solid ${theme.border}` : 'none',
                        }}
                      >
                        <div className="text-xs mb-1" style={{ color: theme.textMuted }}>
                          {formatDate(reply.created_at)}
                        </div>
                        <div className="text-sm leading-normal" style={{ color: theme.text }}>
                          {reply.content.length > 150 ? reply.content.slice(0, 150) + '...' : reply.content}
                        </div>
                      </div>
                    ))}
                    {(item.comment_count ?? 0) > 2 && (
                      <a
                        href={`${item.owner_endpoint}/post/${item.id}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="block mt-2 text-xs no-underline cursor-pointer"
                        style={{ color: theme.link }}
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

