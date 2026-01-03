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

  const buttonClass = `bg-transparent border-0 flex items-center rounded transition-[background] duration-150 ${compact ? 'px-1.5 py-0.5 text-xs gap-1' : 'px-2 py-1 text-sm gap-1'}`

  return (
    <div className={`flex items-center flex-wrap ${compact ? 'gap-1.5' : 'gap-2.5'}`}>
      {/* Like button */}
      <button
        onClick={toggleLike}
        className={buttonClass}
        style={{
          color: hasLiked ? '#e25555' : theme.textMuted,
          background: hasLiked ? 'rgba(226, 85, 85, 0.1)' : 'transparent',
          cursor: loading ? 'wait' : 'pointer',
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
            className={buttonClass}
            style={{
              background: hasReacted ? 'rgba(100, 100, 100, 0.15)' : 'transparent',
              color: theme.textMuted,
              cursor: loading ? 'wait' : 'pointer',
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
      <div className="relative">
        <button
          onClick={() => setShowEmojiPicker(!showEmojiPicker)}
          className={buttonClass}
          style={{
            fontSize: compact ? 11 : 12,
            color: theme.textMuted,
            cursor: loading ? 'wait' : 'pointer',
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
            className="absolute bottom-full left-0 mb-1 p-2 rounded-lg grid grid-cols-4 gap-1 z-[100] shadow-[0_4px_12px_rgba(0,0,0,0.15)]"
            style={{
              background: theme.bgCard,
              border: `1px solid ${theme.border}`,
            }}
          >
            {QUICK_EMOJIS.map(emoji => (
              <button
                key={emoji}
                onClick={() => addEmojiReaction(emoji)}
                className="bg-transparent border-0 cursor-pointer text-lg p-1 rounded"
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
      className="bg-transparent border-0 text-base px-2 py-1 shrink-0"
      style={{
        color: isBookmarked ? theme.accent : theme.textDisabled,
        cursor: loading ? 'wait' : 'pointer',
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
      className="bg-transparent border-0 cursor-pointer text-[11px] px-1 py-0.5 underline decoration-dotted"
      style={{ color: theme.textMuted }}
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
      className="fixed inset-0 flex items-center justify-center z-[1000]"
      style={{ background: 'rgba(0, 0, 0, 0.6)' }}
      onClick={onClose}
    >
      <div
        className="rounded-xl p-6 max-w-[600px] w-[90%] max-h-[80vh] overflow-auto shadow-[0_8px_32px_rgba(0,0,0,0.3)]"
        style={{ background: theme.bgCard }}
        onClick={e => e.stopPropagation()}
      >
        <div className="flex justify-between items-center mb-4">
          <h3 className="m-0" style={{ color: theme.text }}>Edit History</h3>
          <button
            onClick={onClose}
            className="bg-transparent border-0 text-xl cursor-pointer"
            style={{ color: theme.textMuted }}
          >
            ×
          </button>
        </div>

        {loading ? (
          <div className="text-center p-5" style={{ color: theme.textMuted }}>Loading...</div>
        ) : history.length === 0 ? (
          <div className="text-center p-5" style={{ color: theme.textMuted }}>No edit history available</div>
        ) : (
          <div className="flex flex-col gap-4">
            {history.map((entry, index) => (
              <div
                key={entry.id}
                className="p-3 rounded-lg"
                style={{
                  background: theme.bgMuted,
                  border: `1px solid ${theme.border}`,
                }}
              >
                <div className="text-[11px] mb-2" style={{ color: theme.textMuted }}>
                  {index === 0 ? 'Previous version' : `Version ${history.length - index}`} • {formatRelativeTime(entry.edited_at)}
                </div>
                <div className="whitespace-pre-wrap text-sm" style={{ color: theme.text }}>
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
