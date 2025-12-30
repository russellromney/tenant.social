import { useState, useEffect } from 'preact/hooks'
import { Theme } from '../theme'
import { Attribute, Thing } from '../types'
import { apiUrl } from '../api'

// Link Attribute Input Component
export function LinkAttributeInput({
  attribute,
  value,
  onChange,
  theme,
}: {
  attribute: Attribute
  value: unknown
  onChange: (val: unknown) => void
  theme: Theme
}) {
  const [availableThings, setAvailableThings] = useState<Thing[]>([])
  const [searchFilter, setSearchFilter] = useState('')
  const [showDropdown, setShowDropdown] = useState(false)
  const [loading, setLoading] = useState(true)

  const linkedThingIds = Array.isArray(value) ? value : []

  useEffect(() => {
    const fetchThings = async () => {
      try {
        const res = await fetch(apiUrl('/api/things'), { credentials: 'include' })
        const data = await res.json()
        setAvailableThings(data || [])
      } catch (err) {
        console.error('Failed to fetch things:', err)
      } finally {
        setLoading(false)
      }
    }
    fetchThings()
  }, [])

  const filteredThings = availableThings.filter(
    (t: Thing) => !linkedThingIds.includes(t.id) &&
         (t.content?.toLowerCase().includes(searchFilter.toLowerCase()) ||
          t.type?.toLowerCase().includes(searchFilter.toLowerCase()))
  )

  const linkedThings = availableThings.filter((t: Thing) => linkedThingIds.includes(t.id))

  const labelStyle = { fontSize: 13, color: theme.textMuted, marginBottom: 4, display: 'block' }
  const inputStyle = {
    width: '100%',
    padding: '8px 12px',
    border: `1px solid ${theme.borderInput}`,
    borderRadius: 6,
    fontSize: 14,
    boxSizing: 'border-box' as const,
    background: theme.bgInput,
    color: theme.text,
  }

  return (
    <div>
      <label style={labelStyle}>
        {attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}
      </label>

      {/* Selected Things */}
      {linkedThings.length > 0 && (
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, marginBottom: 8 }}>
          {linkedThings.map((thing: Thing) => (
            <div
              key={thing.id}
              style={{
                padding: '6px 10px',
                background: theme.bgMuted,
                borderRadius: 6,
                fontSize: 13,
                color: theme.text,
              }}
            >
              {thing.content || thing.type}
            </div>
          ))}
        </div>
      )}

      {/* Search and Dropdown */}
      <div style={{ position: 'relative' }}>
        <input
          type="text"
          placeholder={loading ? 'Loading...' : 'Search to add...'}
          value={searchFilter}
          onChange={e => setSearchFilter((e.target as HTMLInputElement).value)}
          onFocus={() => setShowDropdown(true)}
          disabled={loading}
          style={inputStyle}
        />

        {/* Dropdown */}
        {showDropdown && filteredThings.length > 0 && (
          <div
            style={{
              position: 'absolute',
              top: '100%',
              left: 0,
              right: 0,
              background: theme.bgCard,
              border: `1px solid ${theme.borderInput}`,
              borderTop: 'none',
              borderRadius: '0 0 6px 6px',
              maxHeight: 200,
              overflowY: 'auto',
              zIndex: 1000,
            }}
          >
            {filteredThings.map((thing: Thing) => (
              <div
                key={thing.id}
                onClick={() => {
                  onChange([...linkedThingIds, thing.id])
                  setSearchFilter('')
                  setShowDropdown(false)
                }}
                style={{
                  padding: '10px 12px',
                  cursor: 'pointer',
                  borderBottom: `1px solid ${theme.border}`,
                  fontSize: 14,
                  color: theme.text,
                }}
                onMouseEnter={e => (e.currentTarget.style.background = theme.bgHover)}
                onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
              >
                {thing.content || thing.type}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// Attribute Input Component
export function AttributeInput({
  attribute,
  value,
  onChange,
  theme,
}: {
  attribute: Attribute
  value: unknown
  onChange: (val: unknown) => void
  theme: Theme
}) {
  const labelStyle = { fontSize: 13, color: theme.textMuted, marginBottom: 4, display: 'block' }
  const inputStyle = {
    width: '100%',
    padding: '8px 12px',
    border: `1px solid ${theme.borderInput}`,
    borderRadius: 6,
    fontSize: 14,
    boxSizing: 'border-box' as const,
    background: theme.bgInput,
    color: theme.text,
  }

  switch (attribute.type) {
    case 'checkbox':
      return (
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, color: theme.text }}>
          <input
            type="checkbox"
            checked={Boolean(value)}
            onChange={e => onChange((e.target as HTMLInputElement).checked)}
          />
          {attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}
        </label>
      )
    case 'select':
      const options = attribute.options.split(',').map(o => o.trim()).filter(Boolean)
      return (
        <div>
          <label style={labelStyle}>{attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}</label>
          <select
            value={String(value || '')}
            onChange={e => onChange((e.target as HTMLSelectElement).value)}
            style={{ ...inputStyle, background: theme.bgInput }}
          >
            <option value="">Select...</option>
            {options.map(opt => (
              <option key={opt} value={opt}>{opt}</option>
            ))}
          </select>
        </div>
      )
    case 'number':
      return (
        <div>
          <label style={labelStyle}>{attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}</label>
          <input
            type="number"
            value={value as number || ''}
            onInput={e => onChange(Number((e.target as HTMLInputElement).value))}
            style={inputStyle}
          />
        </div>
      )
    case 'date':
      return (
        <div>
          <label style={labelStyle}>{attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}</label>
          <input
            type="date"
            value={String(value || '')}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            style={inputStyle}
          />
        </div>
      )
    case 'url':
      return (
        <div>
          <label style={labelStyle}>{attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}</label>
          <input
            type="url"
            value={String(value || '')}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            placeholder="https://..."
            style={inputStyle}
          />
        </div>
      )
    case 'link':
      return <LinkAttributeInput attribute={attribute} value={value} onChange={onChange} theme={theme} />
    default:
      return (
        <div>
          <label style={labelStyle}>{attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}</label>
          <input
            type="text"
            value={String(value || '')}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            style={inputStyle}
          />
        </div>
      )
  }
}
