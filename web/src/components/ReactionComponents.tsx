import { useState, useEffect } from 'preact/hooks'
import { Theme } from '../theme'
import { ReactionSummary, EditHistoryEntry } from '../types'
import { apiUrl } from '../api'
import { formatRelativeTime } from './utils'

// Common emoji reactions for quick picker
const QUICK_EMOJIS = ['❤️', '👍', '😂', '😮', '😢', '🔥', '👏', '🎉']

// ReactionBar - shows and manages reactions for a thing or comment
export function ReactionBar({
  targetId,
  targetType,
  reactions,
  onReactionsChange,
  theme,
  compact = false,
}: {
  targetId: string
  targetType: 'thing' | 'comment'
  reactions: ReactionSummary | null
  onReactionsChange: (reactions: ReactionSummary) => void
  theme: Theme
  compact?: boolean
}) {
  const [loading, setLoading] = useState(false)
  const [showEmojiPicker, setShowEmojiPicker] = useState(false)

  const likeCount = reactions?.counts?.['like'] || 0
  const hasLiked = reactions?.user_reactions?.includes('like') || false

  // Get emoji reactions (excluding 'like')
  const emojiReactions = Object.entries(reactions?.counts || {})
    .filter(([key]) => key !== 'like')
    .sort((a, b) => b[1] - a[1])

  const endpoint = targetType === 'thing'
    ? `/api/things/${targetId}/reactions`
    : `/api/comments/${targetId}/reactions`

  const toggleLike = async () => {
    if (loading) return
    setLoading(true)
    try {
      if (hasLiked) {
        const resp = await fetch(apiUrl(`${endpoint}/like`), { method: 'DELETE', credentials: 'include' })
        if (resp.ok) {
          const data = await resp.json()
          onReactionsChange(data.data)
        }
      } else {
        const resp = await fetch(apiUrl(endpoint), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ reaction_type: 'like' }),
        })
        if (resp.ok) {
          const data = await resp.json()
          onReactionsChange(data.data)
        }
      }
    } finally {
      setLoading(false)
    }
  }

  const addEmojiReaction = async (emoji: string) => {
    if (loading) return
    setLoading(true)
    setShowEmojiPicker(false)
    try {
      // Check if user already has this emoji
      const hasEmoji = reactions?.user_reactions?.includes(emoji)
      if (hasEmoji) {
        // Remove it
        const resp = await fetch(apiUrl(`${endpoint}/${encodeURIComponent(emoji)}`), {
          method: 'DELETE',
          credentials: 'include',
        })
        if (resp.ok) {
          const data = await resp.json()
          onReactionsChange(data.data)
        }
      } else {
        // Add it
        const resp = await fetch(apiUrl(endpoint), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ reaction_type: 'emoji', emoji }),
        })
        if (resp.ok) {
          const data = await resp.json()
          onReactionsChange(data.data)
        }
      }
    } finally {
      setLoading(false)
    }
  }

  const buttonStyle = {
    background: 'none',
    border: 'none',
    cursor: loading ? 'wait' : 'pointer',
    padding: compact ? '2px 6px' : '4px 8px',
    borderRadius: 4,
    fontSize: compact ? 13 : 14,
    display: 'flex',
    alignItems: 'center',
    gap: 4,
    color: theme.textMuted,
    transition: 'background 0.15s',
  }

  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: compact ? 6 : 10, flexWrap: 'wrap' }}>
      {/* Like button */}
      <button
        onClick={toggleLike}
        style={{
          ...buttonStyle,
          color: hasLiked ? '#e25555' : theme.textMuted,
          background: hasLiked ? 'rgba(226, 85, 85, 0.1)' : 'transparent',
        }}
        onMouseEnter={e => { if (!hasLiked) e.currentTarget.style.background = theme.bgMuted }}
        onMouseLeave={e => { if (!hasLiked) e.currentTarget.style.background = 'transparent' }}
        title={hasLiked ? 'Unlike' : 'Like'}
      >
        <span>{hasLiked ? '❤️' : '🤍'}</span>
        {likeCount > 0 && <span>{likeCount}</span>}
      </button>

      {/* Emoji reactions */}
      {emojiReactions.map(([emoji, count]) => {
        const hasReacted = reactions?.user_reactions?.includes(emoji)
        return (
          <button
            key={emoji}
            onClick={() => addEmojiReaction(emoji)}
            style={{
              ...buttonStyle,
              background: hasReacted ? 'rgba(100, 100, 100, 0.15)' : 'transparent',
            }}
            onMouseEnter={e => e.currentTarget.style.background = theme.bgMuted}
            onMouseLeave={e => e.currentTarget.style.background = hasReacted ? 'rgba(100, 100, 100, 0.15)' : 'transparent'}
          >
            <span>{emoji}</span>
            {count > 0 && <span>{count}</span>}
          </button>
        )
      })}

      {/* Add emoji button */}
      <div style={{ position: 'relative' }}>
        <button
          onClick={() => setShowEmojiPicker(!showEmojiPicker)}
          style={{
            ...buttonStyle,
            fontSize: compact ? 11 : 12,
          }}
          onMouseEnter={e => e.currentTarget.style.background = theme.bgMuted}
          onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
          title="Add reaction"
        >
          +
        </button>

        {/* Emoji picker dropdown */}
        {showEmojiPicker && (
          <div
            style={{
              position: 'absolute',
              bottom: '100%',
              left: 0,
              marginBottom: 4,
              background: theme.bgCard,
              border: `1px solid ${theme.border}`,
              borderRadius: 8,
              padding: 8,
              display: 'grid',
              gridTemplateColumns: 'repeat(4, 1fr)',
              gap: 4,
              zIndex: 100,
              boxShadow: '0 4px 12px rgba(0,0,0,0.15)',
            }}
          >
            {QUICK_EMOJIS.map(emoji => (
              <button
                key={emoji}
                onClick={() => addEmojiReaction(emoji)}
                style={{
                  background: 'none',
                  border: 'none',
                  cursor: 'pointer',
                  fontSize: 18,
                  padding: 4,
                  borderRadius: 4,
                }}
                onMouseEnter={e => e.currentTarget.style.background = theme.bgMuted}
                onMouseLeave={e => e.currentTarget.style.background = 'transparent'}
              >
                {emoji}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// BookmarkButton - toggle bookmark for a thing
export function BookmarkButton({
  thingId,
  isBookmarked,
  onBookmarkChange,
  theme,
}: {
  thingId: string
  isBookmarked: boolean
  onBookmarkChange: (bookmarked: boolean) => void
  theme: Theme
}) {
  const [loading, setLoading] = useState(false)

  const toggleBookmark = async () => {
    if (loading) return
    setLoading(true)
    try {
      if (isBookmarked) {
        const resp = await fetch(apiUrl(`/api/bookmarks/${thingId}`), {
          method: 'DELETE',
          credentials: 'include',
        })
        if (resp.ok) {
          onBookmarkChange(false)
        }
      } else {
        const resp = await fetch(apiUrl('/api/bookmarks'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({ thing_id: thingId }),
        })
        if (resp.ok) {
          onBookmarkChange(true)
        }
      }
    } finally {
      setLoading(false)
    }
  }

  return (
    <button
      onClick={(e) => {
        e.stopPropagation()
        toggleBookmark()
      }}
      style={{
        background: 'none',
        border: 'none',
        color: isBookmarked ? theme.accent : theme.textDisabled,
        cursor: loading ? 'wait' : 'pointer',
        fontSize: 16,
        padding: '4px 8px',
        flexShrink: 0,
      }}
      onMouseEnter={e => { if (!isBookmarked) e.currentTarget.style.color = theme.accent }}
      onMouseLeave={e => { if (!isBookmarked) e.currentTarget.style.color = theme.textDisabled }}
      title={isBookmarked ? 'Remove bookmark' : 'Bookmark'}
    >
      {isBookmarked ? '🔖' : '🏷️'}
    </button>
  )
}

// EditedIndicator - shows "edited" with click to view history
export function EditedIndicator({
  editedAt,
  onClick,
  theme,
}: {
  editedAt: string
  onClick: () => void
  theme: Theme
}) {
  return (
    <button
      onClick={(e) => {
        e.stopPropagation()
        onClick()
      }}
      style={{
        background: 'none',
        border: 'none',
        color: theme.textMuted,
        cursor: 'pointer',
        fontSize: 11,
        padding: '2px 4px',
        textDecoration: 'underline',
        textDecorationStyle: 'dotted',
      }}
      title="View edit history"
    >
      edited {formatRelativeTime(editedAt)}
    </button>
  )
}

// EditHistoryModal - shows all previous versions of content
export function EditHistoryModal({
  targetId,
  targetType,
  onClose,
  theme,
}: {
  targetId: string
  targetType: 'thing' | 'comment'
  onClose: () => void
  theme: Theme
}) {
  const [history, setHistory] = useState<EditHistoryEntry[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const endpoint = targetType === 'thing'
          ? `/api/things/${targetId}/history`
          : `/api/comments/${targetId}/history`
        const resp = await fetch(apiUrl(endpoint), { credentials: 'include' })
        if (resp.ok) {
          const data = await resp.json()
          setHistory(data.data || [])
        }
      } finally {
        setLoading(false)
      }
    }
    fetchHistory()
  }, [targetId, targetType])

  // Close on escape
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [onClose])

  return (
    <div
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        right: 0,
        bottom: 0,
        background: 'rgba(0, 0, 0, 0.6)',
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
          maxWidth: 600,
          width: '90%',
          maxHeight: '80vh',
          overflow: 'auto',
          boxShadow: '0 8px 32px rgba(0,0,0,0.3)',
        }}
        onClick={e => e.stopPropagation()}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h3 style={{ margin: 0, color: theme.text }}>Edit History</h3>
          <button
            onClick={onClose}
            style={{
              background: 'none',
              border: 'none',
              fontSize: 20,
              cursor: 'pointer',
              color: theme.textMuted,
            }}
          >
            ×
          </button>
        </div>

        {loading ? (
          <div style={{ color: theme.textMuted, textAlign: 'center', padding: 20 }}>Loading...</div>
        ) : history.length === 0 ? (
          <div style={{ color: theme.textMuted, textAlign: 'center', padding: 20 }}>No edit history available</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {history.map((entry, index) => (
              <div
                key={entry.id}
                style={{
                  padding: 12,
                  background: theme.bgMuted,
                  borderRadius: 8,
                  border: `1px solid ${theme.border}`,
                }}
              >
                <div style={{ fontSize: 11, color: theme.textMuted, marginBottom: 8 }}>
                  {index === 0 ? 'Previous version' : `Version ${history.length - index}`} • {formatRelativeTime(entry.edited_at)}
                </div>
                <div style={{ color: theme.text, whiteSpace: 'pre-wrap', fontSize: 14 }}>
                  {entry.content}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
