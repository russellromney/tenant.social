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

  return (
    <div>
      <label className="block text-[13px] mb-1" style={{ color: theme.textMuted }}>
        {attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}
      </label>

      {/* Selected Things */}
      {linkedThings.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-2">
          {linkedThings.map((thing: Thing) => (
            <div
              key={thing.id}
              className="px-2.5 py-1.5 rounded-md text-[13px]"
              style={{
                background: theme.bgMuted,
                color: theme.text,
              }}
            >
              {thing.content || thing.type}
            </div>
          ))}
        </div>
      )}

      {/* Search and Dropdown */}
      <div className="relative">
        <input
          type="text"
          placeholder={loading ? 'Loading...' : 'Search to add...'}
          value={searchFilter}
          onChange={e => setSearchFilter((e.target as HTMLInputElement).value)}
          onFocus={() => setShowDropdown(true)}
          disabled={loading}
          className="w-full px-3 py-2 rounded-md text-sm border"
          style={{
            background: theme.bgInput,
            color: theme.text,
            borderColor: theme.borderInput,
          }}
        />

        {/* Dropdown */}
        {showDropdown && filteredThings.length > 0 && (
          <div
            data-testid="link-dropdown"
            className="absolute top-full left-0 right-0 border-t-0 rounded-b-md max-h-[200px] overflow-y-auto z-[1000]"
            style={{
              background: theme.bgCard,
              borderColor: theme.borderInput,
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
                className="px-3 py-2.5 cursor-pointer text-sm"
                style={{
                  borderBottom: `1px solid ${theme.border}`,
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
  switch (attribute.type) {
    case 'checkbox':
      return (
        <label className="flex items-center gap-2 text-sm" style={{ color: theme.text }}>
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
          <label className="block text-[13px] mb-1" style={{ color: theme.textMuted }}>
            {attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}
          </label>
          <select
            value={String(value || '')}
            onChange={e => onChange((e.target as HTMLSelectElement).value)}
            className="w-full px-3 py-2 rounded-md text-sm border"
            style={{
              background: theme.bgInput,
              color: theme.text,
              borderColor: theme.borderInput,
            }}
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
          <label className="block text-[13px] mb-1" style={{ color: theme.textMuted }}>
            {attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}
          </label>
          <input
            type="number"
            value={value as number || ''}
            onInput={e => onChange(Number((e.target as HTMLInputElement).value))}
            className="w-full px-3 py-2 rounded-md text-sm border"
            style={{
              background: theme.bgInput,
              color: theme.text,
              borderColor: theme.borderInput,
            }}
          />
        </div>
      )
    case 'date':
      return (
        <div>
          <label className="block text-[13px] mb-1" style={{ color: theme.textMuted }}>
            {attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}
          </label>
          <input
            type="date"
            value={String(value || '')}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            className="w-full px-3 py-2 rounded-md text-sm border"
            style={{
              background: theme.bgInput,
              color: theme.text,
              borderColor: theme.borderInput,
            }}
          />
        </div>
      )
    case 'url':
      return (
        <div>
          <label className="block text-[13px] mb-1" style={{ color: theme.textMuted }}>
            {attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}
          </label>
          <input
            type="url"
            value={String(value || '')}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            placeholder="https://..."
            className="w-full px-3 py-2 rounded-md text-sm border"
            style={{
              background: theme.bgInput,
              color: theme.text,
              borderColor: theme.borderInput,
            }}
          />
        </div>
      )
    case 'link':
      return <LinkAttributeInput attribute={attribute} value={value} onChange={onChange} theme={theme} />
    default:
      return (
        <div>
          <label className="block text-[13px] mb-1" style={{ color: theme.textMuted }}>
            {attribute.name} {attribute.required && <span style={{ color: theme.errorText }}>*</span>}
          </label>
          <input
            type="text"
            value={String(value || '')}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            className="w-full px-3 py-2 rounded-md text-sm border"
            style={{
              background: theme.bgInput,
              color: theme.text,
              borderColor: theme.borderInput,
            }}
          />
        </div>
      )
  }
}
