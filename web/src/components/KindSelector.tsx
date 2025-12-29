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
    <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
      {/* Visible kinds */}
      {visibleKinds.map(kind => {
        const isSelected = kind.name === selectedType
        return (
          <button
            key={kind.id}
            type="button"
            onClick={() => onSelectType(kind.name)}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: 4,
              padding: '5px 10px',
              fontSize: 13,
              border: 'none',
              borderRadius: 4,
              cursor: 'pointer',
              background: isSelected ? theme.accent : theme.bgMuted,
              color: isSelected ? theme.accentText : theme.textSecondary,
              fontWeight: 500,
              transition: 'all 0.15s',
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
          style={{
            padding: '5px 8px',
            fontSize: 13,
            border: 'none',
            borderRadius: 4,
            cursor: 'pointer',
            background: selectedInHidden ? theme.accent : theme.bgMuted,
            color: selectedInHidden ? theme.accentText : theme.textMuted,
            fontWeight: 500,
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
