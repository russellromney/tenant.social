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
    <div className="relative">
      <button
        type="button"
        onClick={() => setIsOpen(!isOpen)}
        className="w-[50px] h-[42px] border rounded-md text-xl cursor-pointer flex items-center justify-center"
        style={{
          borderColor: theme.borderInput,
          background: theme.bgInput,
        }}
      >
        {value || '➕'}
      </button>

      {isOpen && (
        <div
          className="absolute top-full left-0 mt-1 border rounded-lg z-[100] w-80 flex flex-col"
          style={{
            background: theme.bgCard,
            borderColor: theme.borderInput,
            boxShadow: `0 4px 12px ${theme.shadowStrong}`,
          }}
        >
          {/* Search */}
          <input
            type="text"
            value={search}
            onInput={e => setSearch((e.target as HTMLInputElement).value)}
            placeholder="Search emojis..."
            autoFocus
            className="w-full px-3 py-2 border-0 border-b rounded-t-lg text-sm outline-none flex-shrink-0"
            style={{
              borderBottomColor: theme.border,
              background: theme.bgCard,
              color: theme.text,
            }}
          />

          {/* Category tabs */}
          {!search.trim() && (
            <div className="flex p-1 pt-1 pb-0 gap-0.5" style={{ borderBottom: `1px solid ${theme.border}` }}>
              {EMOJI_CATEGORIES.map((cat, i) => (
                <button
                  key={cat.name}
                  type="button"
                  onClick={() => setSelectedCategory(i)}
                  title={cat.name}
                  className="flex-1 px-0.5 py-1.5 border-0 rounded-t cursor-pointer text-base"
                  style={{
                    background: selectedCategory === i ? theme.bgMuted : 'transparent',
                    opacity: selectedCategory === i ? 1 : 0.6,
                  }}
                >
                  {cat.icon}
                </button>
              ))}
            </div>
          )}

          {/* Emojis grid */}
          <div className="grid grid-cols-8 gap-0.5 p-2 h-[220px] overflow-y-scroll content-start">
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
                  className="w-8 h-8 border-0 rounded text-xl flex items-center justify-center"
                  style={{
                    background: value === emoji ? theme.bgMuted : 'transparent',
                    cursor: isUsed ? 'not-allowed' : 'pointer',
                    opacity: isUsed ? 0.3 : 1,
                  }}
                  title={isUsed ? 'Already in use' : emoji}
                >
                  {emoji}
                </button>
              )
            })}
            {displayEmojis.length === 0 && (
              <div className="col-span-full p-3 text-center text-[13px]" style={{ color: theme.textSubtle }}>
                No emojis found
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
