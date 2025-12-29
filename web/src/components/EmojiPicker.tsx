import { useState } from 'preact/hooks'
import { EMOJI_CATEGORIES, ALL_EMOJIS } from '../emojis'
import { Theme } from '../theme'

interface EmojiPickerProps {
  value: string
  onChange: (emoji: string) => void
  usedEmojis: string[]
  theme: Theme
}

export function EmojiPicker({
  value,
  onChange,
  usedEmojis,
  theme,
}: EmojiPickerProps) {
  const [isOpen, setIsOpen] = useState(false)
  const [search, setSearch] = useState('')
  const [selectedCategory, setSelectedCategory] = useState(0)

  // Filter emojis by search or show category
  const displayEmojis = search.trim()
    ? ALL_EMOJIS.filter(e => e.keywords.toLowerCase().includes(search.toLowerCase()))
    : EMOJI_CATEGORIES[selectedCategory].emojis

  return (
    <div style={{ position: 'relative' }}>
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        style={{
          width: 50,
          height: 42,
          border: `1px solid ${theme.borderInput}`,
          borderRadius: 6,
          background: theme.bgInput,
          fontSize: 20,
          cursor: 'pointer',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
        }}
      >
        {value || '➕'}
      </button>

      {isOpen && (
        <div
          style={{
            position: 'absolute',
            top: '100%',
            left: 0,
            marginTop: 4,
            background: theme.bgCard,
            border: `1px solid ${theme.borderInput}`,
            borderRadius: 8,
            boxShadow: `0 4px 12px ${theme.shadowStrong}`,
            zIndex: 100,
            width: 320,
            display: 'flex',
            flexDirection: 'column',
          }}
        >
          {/* Search */}
          <input
            type="text"
            value={search}
            onInput={e => setSearch((e.target as HTMLInputElement).value)}
            placeholder="Search emojis..."
            autoFocus
            style={{
              width: '100%',
              padding: '8px 12px',
              border: 'none',
              borderBottom: `1px solid ${theme.border}`,
              borderRadius: '8px 8px 0 0',
              fontSize: 14,
              boxSizing: 'border-box',
              outline: 'none',
              flexShrink: 0,
              background: theme.bgCard,
              color: theme.text,
            }}
          />

          {/* Category tabs */}
          {!search.trim() && (
            <div style={{ display: 'flex', borderBottom: `1px solid ${theme.border}`, padding: '4px 4px 0', gap: 2 }}>
              {EMOJI_CATEGORIES.map((cat, i) => (
                <button
                  key={cat.name}
                  type="button"
                  onClick={() => setSelectedCategory(i)}
                  title={cat.name}
                  style={{
                    flex: 1,
                    padding: '6px 2px',
                    border: 'none',
                    background: selectedCategory === i ? theme.bgMuted : 'transparent',
                    borderRadius: '4px 4px 0 0',
                    cursor: 'pointer',
                    fontSize: 16,
                    opacity: selectedCategory === i ? 1 : 0.6,
                  }}
                >
                  {cat.icon}
                </button>
              ))}
            </div>
          )}

          {/* Emojis grid */}
          <div
            style={{
              display: 'grid',
              gridTemplateColumns: 'repeat(8, 1fr)',
              gap: 2,
              padding: 8,
              height: 220,
              overflowY: 'scroll',
              alignContent: 'start',
            }}
          >
            {displayEmojis.map(({ emoji }) => {
              const isUsed = usedEmojis.includes(emoji)
              return (
                <button
                  key={emoji}
                  type="button"
                  onClick={() => {
                    if (!isUsed) {
                      onChange(emoji)
                      setIsOpen(false)
                      setSearch('')
                    }
                  }}
                  style={{
                    width: 32,
                    height: 32,
                    border: 'none',
                    background: value === emoji ? theme.bgMuted : 'transparent',
                    borderRadius: 4,
                    cursor: isUsed ? 'not-allowed' : 'pointer',
                    opacity: isUsed ? 0.3 : 1,
                    fontSize: 20,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                  }}
                  title={isUsed ? 'Already in use' : emoji}
                >
                  {emoji}
                </button>
              )
            })}
            {displayEmojis.length === 0 && (
              <div style={{ gridColumn: '1 / -1', padding: 12, textAlign: 'center', color: theme.textSubtle, fontSize: 13 }}>
                No emojis found
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
