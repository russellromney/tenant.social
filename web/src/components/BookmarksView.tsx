import { useState, useEffect } from 'preact/hooks'
import { Theme } from '../theme'
import { Kind, Thing } from '../types'
import { apiUrl } from '../api'
import { ThingCard } from './ThingCard'

export function BookmarksView({
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
      <div className="p-8 text-center" style={{ color: theme.textMuted }}>
        Loading bookmarks...
      </div>
    )
  }

  if (error) {
    return (
      <div className="p-8 text-center" style={{ color: theme.error }}>
        {error}
      </div>
    )
  }

  return (
    <div>
      <h2 className="mb-4 text-xl" style={{ color: theme.text }}>
        Bookmarks
      </h2>
      {bookmarks.length === 0 ? (
        <div className="p-8 text-center rounded-xl border" style={{
          color: theme.textMuted,
          background: theme.bgCard,
          borderColor: theme.border,
        }}>
          <p className="mb-2">No bookmarks yet</p>
          <p className="text-sm">Bookmark things to save them for later</p>
        </div>
      ) : (
        <div className="flex flex-col gap-4">
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

