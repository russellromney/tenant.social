import { useState } from 'preact/hooks'
import { Theme } from '../theme'
import { Thing, Kind, Attribute } from '../types'
import { apiUrl } from '../api'

// Attribute input component for editing metadata
function AttributeInput({
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
  const commonStyle = {
    width: '100%',
    padding: '10px 14px',
    border: `1px solid ${theme.borderInput}`,
    borderRadius: 6,
    fontSize: 14,
    boxSizing: 'border-box' as const,
    background: theme.bgInput,
    color: theme.text,
  }

  switch (attribute.type) {
    case 'number':
      return (
        <div>
          <label style={{ display: 'block', marginBottom: 4, fontSize: 13, color: theme.textSubtle }}>
            {attribute.name}{attribute.required && ' *'}
          </label>
          <input
            type="number"
            value={value as number || ''}
            onInput={e => onChange(parseFloat((e.target as HTMLInputElement).value) || null)}
            style={commonStyle}
          />
        </div>
      )
    case 'date':
      return (
        <div>
          <label style={{ display: 'block', marginBottom: 4, fontSize: 13, color: theme.textSubtle }}>
            {attribute.name}{attribute.required && ' *'}
          </label>
          <input
            type="date"
            value={value as string || ''}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            style={commonStyle}
          />
        </div>
      )
    case 'url':
      return (
        <div>
          <label style={{ display: 'block', marginBottom: 4, fontSize: 13, color: theme.textSubtle }}>
            {attribute.name}{attribute.required && ' *'}
          </label>
          <input
            type="url"
            value={value as string || ''}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            placeholder="https://..."
            style={commonStyle}
          />
        </div>
      )
    case 'checkbox':
      return (
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
          <input
            type="checkbox"
            checked={value as boolean || false}
            onChange={e => onChange((e.target as HTMLInputElement).checked)}
            style={{ width: 18, height: 18, cursor: 'pointer' }}
          />
          <span style={{ fontSize: 14, color: theme.text }}>{attribute.name}</span>
        </label>
      )
    case 'select':
      const options = attribute.options?.split(',').map(o => o.trim()).filter(Boolean) || []
      return (
        <div>
          <label style={{ display: 'block', marginBottom: 4, fontSize: 13, color: theme.textSubtle }}>
            {attribute.name}{attribute.required && ' *'}
          </label>
          <select
            value={value as string || ''}
            onChange={e => onChange((e.target as HTMLSelectElement).value)}
            style={commonStyle}
          >
            <option value="">Select...</option>
            {options.map(opt => (
              <option key={opt} value={opt}>{opt}</option>
            ))}
          </select>
        </div>
      )
    default:
      return (
        <div>
          <label style={{ display: 'block', marginBottom: 4, fontSize: 13, color: theme.textSubtle }}>
            {attribute.name}{attribute.required && ' *'}
          </label>
          <input
            type="text"
            value={value as string || ''}
            onInput={e => onChange((e.target as HTMLInputElement).value)}
            style={commonStyle}
          />
        </div>
      )
  }
}

interface EditThingModalProps {
  thing: Thing
  kinds: Kind[]
  onSave: (t: Thing) => void
  onClose: () => void
  theme: Theme
}

export function EditThingModal({
  thing,
  kinds,
  onSave,
  onClose,
  theme,
}: EditThingModalProps) {
  const [content, setContent] = useState(thing.content)
  const [type, setType] = useState(thing.type)
  const [metadata, setMetadata] = useState<Record<string, unknown>>(thing.metadata || {})
  const [photoCaptions, setPhotoCaptions] = useState<Record<string, string>>(
    thing.photos?.reduce((acc, p) => ({ ...acc, [p.id]: p.caption || '' }), {}) || {}
  )
  const [deletedPhotoIds, setDeletedPhotoIds] = useState<string[]>([])
  const [saving, setSaving] = useState(false)

  const currentKind = kinds.find(k => k.name === type)
  const isGallery = thing.type === 'gallery' && thing.photos && thing.photos.length > 0

  // Filter out deleted photos for display
  const visiblePhotos = thing.photos?.filter(p => !deletedPhotoIds.includes(p.id)) || []

  async function handleSave(e: Event) {
    e.preventDefault()
    setSaving(true)

    try {
      // Delete photos that were marked for deletion
      for (const photoId of deletedPhotoIds) {
        await fetch(apiUrl(`/api/photos/${photoId}`), {
          method: 'DELETE',
          credentials: 'include',
        })
      }

      // Save photo captions if this is a gallery
      if (isGallery && thing.photos) {
        for (const photo of thing.photos) {
          // Skip deleted photos
          if (deletedPhotoIds.includes(photo.id)) continue

          const newCaption = photoCaptions[photo.id] || ''
          if (newCaption !== (photo.caption || '')) {
            await fetch(apiUrl(`/api/photos/${photo.id}`), {
              method: 'PUT',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ caption: newCaption }),
              credentials: 'include',
            })
          }
        }
      }

      // Build updated photos array with new captions, excluding deleted photos
      const updatedPhotos = thing.photos
        ?.filter(p => !deletedPhotoIds.includes(p.id))
        .map(p => ({ ...p, caption: photoCaptions[p.id] || p.caption }))

      // Save the thing with updated photos
      onSave({ ...thing, content, type, metadata, photos: updatedPhotos })
    } catch (err) {
      console.error('Failed to save:', err)
    } finally {
      setSaving(false)
    }
  }

  return (
    <div
      style={{
        position: 'fixed',
        inset: 0,
        background: theme.overlay,
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
          width: '100%',
          maxWidth: 500,
          maxHeight: '80vh',
          overflow: 'auto',
        }}
        onClick={e => e.stopPropagation()}
      >
        <h2 style={{ margin: '0 0 20px', fontSize: 20, color: theme.text }}>Edit Thing</h2>
        <form onSubmit={handleSave}>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500, color: theme.text }}>Kind</label>
            <select
              value={type}
              onChange={e => {
                setType((e.target as HTMLSelectElement).value)
                setMetadata({})
              }}
              style={{
                width: '100%',
                padding: '10px 14px',
                border: `1px solid ${theme.borderInput}`,
                borderRadius: 6,
                fontSize: 14,
                background: theme.bgInput,
                color: theme.text,
              }}
            >
              {kinds.map(kind => (
                <option key={kind.id} value={kind.name}>{kind.icon} {kind.name}</option>
              ))}
            </select>
          </div>
          <div style={{ marginBottom: 16 }}>
            <label style={{ display: 'block', marginBottom: 6, fontSize: 14, fontWeight: 500, color: theme.text }}>Content</label>
            <textarea
              value={content}
              onInput={e => setContent((e.target as HTMLTextAreaElement).value)}
              rows={4}
              style={{
                width: '100%',
                padding: '10px 14px',
                border: `1px solid ${theme.borderInput}`,
                borderRadius: 6,
                fontSize: 14,
                resize: 'vertical',
                boxSizing: 'border-box',
                background: theme.bgInput,
                color: theme.text,
              }}
            />
          </div>

          {/* Kind attributes */}
          {currentKind?.attributes && currentKind.attributes.length > 0 && (
            <div style={{ marginBottom: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <label style={{ fontSize: 14, fontWeight: 500, color: theme.text }}>Attributes</label>
              {currentKind.attributes.map(attr => (
                <AttributeInput
                  key={attr.name}
                  attribute={attr}
                  value={metadata[attr.name]}
                  onChange={val => setMetadata({ ...metadata, [attr.name]: val })}
                  theme={theme}
                />
              ))}
            </div>
          )}

          {/* Photo captions for galleries */}
          {isGallery && visiblePhotos.length > 0 && (
            <div style={{ marginBottom: 16 }}>
              <label style={{ display: 'block', marginBottom: 8, fontSize: 14, fontWeight: 500, color: theme.text }}>
                Photos ({visiblePhotos.length})
              </label>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                {visiblePhotos.map((photo, index) => (
                  <div key={photo.id} style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                    <img
                      src={apiUrl(`/api/photos/${photo.id}?size=thumb`)}
                      alt={`Photo ${index + 1}`}
                      style={{
                        width: 60,
                        height: 60,
                        objectFit: 'cover',
                        borderRadius: 4,
                        flexShrink: 0,
                      }}
                    />
                    <input
                      type="text"
                      value={photoCaptions[photo.id] || ''}
                      onChange={e => setPhotoCaptions({ ...photoCaptions, [photo.id]: (e.target as HTMLInputElement).value })}
                      placeholder={`Caption for photo ${index + 1}`}
                      style={{
                        flex: 1,
                        padding: '8px 12px',
                        border: `1px solid ${theme.borderInput}`,
                        borderRadius: 6,
                        fontSize: 13,
                        background: theme.bgInput,
                        color: theme.text,
                      }}
                    />
                    <button
                      type="button"
                      onClick={() => setDeletedPhotoIds([...deletedPhotoIds, photo.id])}
                      style={{
                        background: 'none',
                        border: 'none',
                        color: theme.error,
                        cursor: 'pointer',
                        fontSize: 18,
                        padding: '4px 8px',
                        flexShrink: 0,
                      }}
                      title="Delete photo"
                    >
                      🗑️
                    </button>
                  </div>
                ))}
              </div>
              {deletedPhotoIds.length > 0 && (
                <p style={{ fontSize: 12, color: theme.textMuted, marginTop: 8 }}>
                  {deletedPhotoIds.length} photo(s) will be deleted when you save
                </p>
              )}
            </div>
          )}

          <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
            <button
              type="button"
              onClick={onClose}
              style={{
                padding: '10px 20px',
                background: theme.bgHover,
                color: theme.text,
                border: 'none',
                borderRadius: 6,
                cursor: 'pointer',
              }}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={saving}
              style={{
                padding: '10px 20px',
                background: saving ? theme.textMuted : theme.accent,
                color: theme.accentText,
                border: 'none',
                borderRadius: 6,
                cursor: saving ? 'not-allowed' : 'pointer',
                opacity: saving ? 0.7 : 1,
              }}
            >
              {saving ? 'Saving...' : 'Save'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
