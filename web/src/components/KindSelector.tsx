import { Kind } from '../types'
import { Theme } from '../theme'

interface KindSelectorProps {
  kinds: Kind[]
  selectedType: string
  onSelectType: (type: string) => void
  visibleCount: number
  theme: Theme
}

export function KindSelector({
  kinds,
  selectedType,
  onSelectType,
  visibleCount,
  theme,
}: KindSelectorProps) {
  const visibleKinds = kinds.slice(0, visibleCount)
  const hiddenKinds = kinds.slice(visibleCount)
  const selectedKind = kinds.find(k => k.name === selectedType)
  const selectedInHidden = hiddenKinds.some(k => k.name === selectedType)

  return (
    <div className="flex gap-1.5 flex-wrap items-center">
      {/* Visible kinds */}
      {visibleKinds.map(kind => {
        const isSelected = kind.name === selectedType
        return (
          <button
            key={kind.id}
            type="button"
            onClick={() => onSelectType(kind.name)}
            className="flex items-center gap-1 px-2.5 py-1.5 text-[13px] border-0 rounded cursor-pointer font-medium transition-all duration-150"
            style={{
              background: isSelected ? theme.accent : theme.bgMuted,
              color: isSelected ? theme.accentText : theme.textSecondary,
            }}
          >
            <span>{kind.icon}</span>
            <span>{kind.name}</span>
          </button>
        )
      })}

      {/* Native select dropdown for hidden kinds */}
      {hiddenKinds.length > 0 && (
        <select
          value={selectedInHidden ? selectedType : ''}
          onChange={e => {
            if (e.currentTarget.value) {
              onSelectType(e.currentTarget.value)
            }
          }}
          className="px-2 py-1.5 text-[13px] border-0 rounded cursor-pointer font-medium"
          style={{
            background: selectedInHidden ? theme.accent : theme.bgMuted,
            color: selectedInHidden ? theme.accentText : theme.textMuted,
          }}
        >
          <option value="" disabled={selectedInHidden}>
            {selectedInHidden && selectedKind ? `${selectedKind.icon} ${selectedKind.name}` : 'More...'}
          </option>
          {hiddenKinds.map(kind => (
            <option key={kind.id} value={kind.name}>
              {kind.icon} {kind.name}
            </option>
          ))}
        </select>
      )}
    </div>
  )
}
